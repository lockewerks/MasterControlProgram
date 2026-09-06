use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::File,
    mem::size_of,
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::OwnedHandle,
    },
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::{bail, Context};
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::{
        Foundation::{
            SetHandleInformation, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, HANDLE, HANDLE_FLAGS,
            HANDLE_FLAG_INHERIT, WAIT_OBJECT_0, WAIT_TIMEOUT,
        },
        Globalization::{CompareStringOrdinal, CSTR_EQUAL, CSTR_LESS_THAN},
        Security::SECURITY_ATTRIBUTES,
        Storage::FileSystem::SearchPathW,
        System::{
            Console::{ClosePseudoConsole, CreatePseudoConsole, ResizePseudoConsole, COORD, HPCON},
            JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicAccountingInformation,
                JobObjectExtendedLimitInformation, QueryInformationJobObject,
                SetInformationJobObject, TerminateJobObject,
                JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            },
            Pipes::CreatePipe,
            SystemInformation::{GetSystemDirectoryW, GetWindowsDirectoryW},
            Threading::{
                CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
                InitializeProcThreadAttributeList, QueryFullProcessImageNameW, ResumeThread,
                TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject, CREATE_NO_WINDOW,
                CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT,
                LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION, PROCESS_NAME_FORMAT,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                STARTF_USESTDHANDLES, STARTUPINFOEXW,
            },
        },
    },
};

use super::{JobStartInput, StartupCancellation, Stream};
use crate::context::{own, process_creation_time, raw};

pub(super) const CANCEL_EXIT_CODE: u32 = 0xc000013a;

struct AttributeList {
    _storage: Vec<usize>,
    pointer: LPPROC_THREAD_ATTRIBUTE_LIST,
}

impl AttributeList {
    fn new() -> anyhow::Result<Self> {
        let mut size = 0;
        let probe = unsafe { InitializeProcThreadAttributeList(None, 1, None, &mut size) };
        if size == 0 || size > 1_048_576 {
            probe?;
            bail!("invalid startup attribute allocation size");
        }
        let mut storage = vec![0usize; size.div_ceil(size_of::<usize>())];
        let pointer = LPPROC_THREAD_ATTRIBUTE_LIST(storage.as_mut_ptr().cast());
        unsafe { InitializeProcThreadAttributeList(Some(pointer), 1, None, &mut size)? };
        Ok(Self {
            _storage: storage,
            pointer,
        })
    }

    unsafe fn set(
        &self,
        attribute: u32,
        pointer: *const core::ffi::c_void,
        size: usize,
    ) -> anyhow::Result<()> {
        unsafe {
            UpdateProcThreadAttribute(
                self.pointer,
                0,
                attribute as usize,
                Some(pointer),
                size,
                None,
                None,
            )?;
        }
        Ok(())
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        unsafe { DeleteProcThreadAttributeList(self.pointer) };
    }
}

struct PseudoConsole(HPCON);

impl Drop for PseudoConsole {
    fn drop(&mut self) {
        unsafe { ClosePseudoConsole(self.0) };
    }
}

pub(super) struct NativeProcess {
    process: OwnedHandle,
    job: OwnedHandle,
    pty: Mutex<Option<PseudoConsole>>,
    pub pid: u32,
    pub creation_time: u64,
    pub program: String,
    pub cwd: String,
}

pub(super) struct CreatedProcess {
    pub process: Arc<NativeProcess>,
    thread: Option<OwnedHandle>,
    pub stdin: Option<File>,
    pub readers: Vec<(Stream, File)>,
}

impl CreatedProcess {
    pub fn resume(&mut self) -> anyhow::Result<()> {
        let thread = self
            .thread
            .as_ref()
            .context("process was already resumed")?;
        let previous = unsafe { ResumeThread(raw(thread)) };
        match previous {
            1 => {}
            u32::MAX => return Err(windows::core::Error::from_thread().into()),
            _ => bail!("owned primary thread has unexpected suspend count {previous}; process will be terminated"),
        }
        self.thread.take();
        Ok(())
    }
}

impl Drop for CreatedProcess {
    fn drop(&mut self) {
        if self.thread.is_some() {
            if let Err(error) = self.process.terminate() {
                tracing::error!(pid = self.process.pid, %error, "failed to terminate unresumed owned process");
            }
            self.readers.clear();
            self.stdin.take();
            self.process.close_pty();
        }
    }
}

impl NativeProcess {
    pub fn sample(&self) -> anyhow::Result<(Option<u32>, u32)> {
        let exit = match unsafe { WaitForSingleObject(raw(&self.process), 0) } {
            WAIT_OBJECT_0 => {
                let mut code = 0;
                unsafe { GetExitCodeProcess(raw(&self.process), &mut code)? };
                Some(code)
            }
            WAIT_TIMEOUT => None,
            _ => return Err(windows::core::Error::from_thread().into()),
        };
        let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        unsafe {
            QueryInformationJobObject(
                Some(raw(&self.job)),
                JobObjectBasicAccountingInformation,
                (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                None,
            )?;
        }
        Ok((exit, accounting.ActiveProcesses))
    }

    pub fn terminate(&self) -> anyhow::Result<()> {
        unsafe { TerminateJobObject(raw(&self.job), CANCEL_EXIT_CODE)? };
        Ok(())
    }

    pub fn resize(&self, cols: u16, rows: u16) -> anyhow::Result<()> {
        let pty = self.pty.lock().expect("pseudoconsole mutex poisoned");
        let pty = pty.as_ref().context("terminal pseudoconsole is closed")?;
        unsafe {
            ResizePseudoConsole(
                pty.0,
                COORD {
                    X: cols as i16,
                    Y: rows as i16,
                },
            )?
        };
        Ok(())
    }

    pub fn close_pty(&self) {
        // The output reader remains live while ClosePseudoConsole flushes its final VT output.
        let pty = self
            .pty
            .lock()
            .expect("pseudoconsole mutex poisoned")
            .take();
        drop(pty);
    }

    #[cfg(test)]
    pub fn process_handle(&self) -> HANDLE {
        raw(&self.process)
    }
}

impl Drop for NativeProcess {
    fn drop(&mut self) {
        // KILL_ON_JOB_CLOSE also covers abrupt host termination. This path bounds normal cleanup.
        if let Err(error) = self.terminate() {
            tracing::error!(pid = self.pid, %error, "failed to terminate owned job during cleanup");
        }
        self.close_pty();
    }
}

fn pipe(inherit: bool) -> anyhow::Result<(OwnedHandle, OwnedHandle)> {
    let mut read = HANDLE::default();
    let mut write = HANDLE::default();
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        bInheritHandle: inherit.into(),
        ..Default::default()
    };
    unsafe {
        CreatePipe(&mut read, &mut write, Some(&attributes), 65536)?;
        Ok((own(read), own(write)))
    }
}

fn non_inheritable(handle: &OwnedHandle) -> anyhow::Result<()> {
    unsafe { SetHandleInformation(raw(handle), HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0))? };
    Ok(())
}

fn wide(value: &std::ffi::OsStr) -> anyhow::Result<Vec<u16>> {
    let mut value: Vec<_> = value.encode_wide().collect();
    anyhow::ensure!(!value.contains(&0), "process input contains a NUL");
    value.push(0);
    Ok(value)
}

pub(super) fn quote_argument(argument: &str) -> String {
    if !argument.is_empty() && !argument.contains([' ', '\t', '"']) {
        return argument.into();
    }
    let mut quoted = String::from("\"");
    let mut backslashes = 0;
    for character in argument.chars() {
        if character == '\\' {
            backslashes += 1;
        } else {
            quoted.extend(std::iter::repeat_n(
                '\\',
                backslashes * if character == '"' { 2 } else { 1 },
            ));
            if character == '"' {
                quoted.push('\\');
            }
            backslashes = 0;
            quoted.push(character);
        }
    }
    quoted.extend(std::iter::repeat_n('\\', backslashes * 2));
    quoted.push('"');
    quoted
}

fn env_compare(left: &OsString, right: &OsString) -> std::cmp::Ordering {
    let left: Vec<_> = left.encode_wide().collect();
    let right: Vec<_> = right.encode_wide().collect();
    match unsafe { CompareStringOrdinal(&left, &right, true) } {
        CSTR_LESS_THAN => std::cmp::Ordering::Less,
        CSTR_EQUAL => std::cmp::Ordering::Equal,
        _ => std::cmp::Ordering::Greater,
    }
}

fn environment(
    overrides: &BTreeMap<String, Option<String>>,
) -> anyhow::Result<(Vec<u16>, Option<OsString>)> {
    let mut variables: Vec<_> = std::env::vars_os().collect();
    for (name, value) in overrides {
        anyhow::ensure!(
            !name.is_empty() && !name.contains(['=', '\0']),
            "invalid environment variable name"
        );
        let name = OsString::from(name);
        variables.retain(|(key, _)| !env_compare(key, &name).is_eq());
        if let Some(value) = value {
            anyhow::ensure!(!value.contains('\0'), "environment value contains a NUL");
            variables.push((name, value.into()));
        }
    }
    variables.sort_by(|(left, _), (right, _)| env_compare(left, right));
    let path_key = OsString::from("PATH");
    let search_path = variables
        .iter()
        .find(|(key, _)| env_compare(key, &path_key).is_eq())
        .map(|(_, value)| value.clone());
    let mut block = Vec::new();
    for (name, value) in variables {
        block.extend(name.encode_wide());
        block.push(b'=' as u16);
        block.extend(value.encode_wide());
        block.push(0);
        anyhow::ensure!(
            block.len() <= 1_048_576,
            "process environment exceeds one million UTF-16 units"
        );
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    anyhow::ensure!(
        block.len() <= 1_048_576,
        "process environment exceeds one million UTF-16 units"
    );
    Ok((block, search_path))
}

fn windows_directory(system: bool) -> anyhow::Result<PathBuf> {
    let mut buffer = vec![0u16; 32768];
    let length = unsafe {
        if system {
            GetSystemDirectoryW(Some(&mut buffer))
        } else {
            GetWindowsDirectoryW(Some(&mut buffer))
        }
    } as usize;
    if length == 0 {
        return Err(windows::core::Error::from_thread().into());
    }
    anyhow::ensure!(
        length < buffer.len(),
        "Windows system directory exceeds the path limit"
    );
    Ok(PathBuf::from(OsString::from_wide(&buffer[..length])))
}

fn find_program(candidate: &Path) -> anyhow::Result<Option<Vec<u16>>> {
    let candidate = wide(candidate.as_os_str())?;
    let mut found = vec![0u16; 32768];
    let length = unsafe {
        SearchPathW(
            PCWSTR::null(),
            PCWSTR(candidate.as_ptr()),
            windows::core::w!(".exe"),
            Some(&mut found),
            None,
        )
    } as usize;
    if length == 0 {
        let error = windows::core::Error::from_thread();
        if error.code() == ERROR_FILE_NOT_FOUND.to_hresult()
            || error.code() == ERROR_PATH_NOT_FOUND.to_hresult()
        {
            return Ok(None);
        }
        return Err(error.into());
    }
    anyhow::ensure!(
        length < found.len(),
        "executable path exceeds 32767 UTF-16 units"
    );
    found.truncate(length + 1);
    Ok(Some(found))
}

fn resolve_program(
    program: &str,
    cwd: &Path,
    search_path: Option<&OsString>,
    cancel: &StartupCancellation,
) -> anyhow::Result<Vec<u16>> {
    let path = Path::new(program);
    let candidates = if program.contains(['\\', '/', ':']) {
        vec![std::path::absolute(cwd.join(path))?]
    } else {
        let exe = std::env::current_exe()?;
        let mut directories = vec![
            exe.parent()
                .context("current executable has no parent")?
                .to_path_buf(),
            cwd.to_path_buf(),
            windows_directory(true)?,
            windows_directory(false)?,
        ];
        if let Some(search_path) = search_path {
            for directory in std::env::split_paths(search_path) {
                anyhow::ensure!(
                    directories.len() < 1028,
                    "executable PATH exceeds 1024 directories"
                );
                directories.push(std::path::absolute(cwd.join(directory))?);
            }
        }
        directories
            .into_iter()
            .map(|directory| directory.join(path))
            .collect()
    };
    for candidate in candidates {
        cancel.check().context("during executable resolution")?;
        if let Some(program) = find_program(&candidate)? {
            cancel.check().context("after executable resolution")?;
            return Ok(program);
        }
    }
    Err(anyhow::Error::from(windows::core::Error::from_hresult(ERROR_FILE_NOT_FOUND.to_hresult()))
        .context(format!("executable {program:?} was not found in the selected cwd, Windows directories or effective PATH")))
}

pub(super) fn create(
    input: &JobStartInput,
    size: Option<(u16, u16)>,
    cancel: &StartupCancellation,
) -> anyhow::Result<CreatedProcess> {
    cancel.check()?;
    let command = std::iter::once(quote_argument(&input.program))
        .chain(input.args.iter().map(|arg| quote_argument(arg)))
        .collect::<Vec<_>>()
        .join(" ");
    let mut command = wide(std::ffi::OsStr::new(&command))?;
    anyhow::ensure!(
        command.len() <= 32767,
        "Windows command line exceeds 32767 UTF-16 units"
    );
    let cwd = match &input.cwd {
        Some(directory) => std::path::absolute(PathBuf::from(directory))
            .context("resolve process working directory")?,
        None => std::env::current_dir()?,
    };
    anyhow::ensure!(
        std::fs::metadata(&cwd)?.is_dir(),
        "working directory is not a directory"
    );
    let cwd_wide = wide(cwd.as_os_str())?;
    let (env, search_path) = environment(&input.env)?;
    let program = resolve_program(&input.program, &cwd, search_path.as_ref(), cancel)?;
    #[cfg(test)]
    cancel.pause(super::tests::StartupPhase::AfterPreflight, None)?;
    cancel.check().context("before process creation")?;
    let job = unsafe { own(CreateJobObjectW(None, PCWSTR::null())?) };
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    unsafe {
        SetInformationJobObject(
            raw(&job),
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )?;
    }
    let attributes = AttributeList::new()?;
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    // Null standard handles prevent a ConPTY child from inheriting the host's
    // real console handles. Piped jobs replace these with their explicit handles.
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.lpAttributeList = attributes.pointer;
    let (input_read, input_write) = pipe(size.is_none())?;
    let (output_read, output_write) = pipe(size.is_none())?;
    let mut child_handles = Vec::new();
    let mut readers = Vec::new();
    let pty = if let Some((cols, rows)) = size {
        let pty = PseudoConsole(
            unsafe {
                CreatePseudoConsole(
                    COORD {
                        X: cols as i16,
                        Y: rows as i16,
                    },
                    raw(&input_read),
                    raw(&output_write),
                    0,
                )
            }
            .context("ConPTY CreatePseudoConsole is unavailable or failed")?,
        );
        if let Err(error) = unsafe {
            attributes.set(
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                pty.0 .0 as *const _,
                size_of::<HPCON>(),
            )
        } {
            drop(output_read);
            drop(pty);
            return Err(error);
        }
        readers.push((Stream::Combined, File::from(output_read)));
        Some(pty)
    } else {
        non_inheritable(&input_write)?;
        non_inheritable(&output_read)?;
        let (error_read, error_write) = pipe(true)?;
        non_inheritable(&error_read)?;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = raw(&input_read);
        startup.StartupInfo.hStdOutput = raw(&output_write);
        startup.StartupInfo.hStdError = raw(&error_write);
        child_handles.push(error_write);
        readers.push((Stream::Stdout, File::from(output_read)));
        readers.push((Stream::Stderr, File::from(error_read)));
        None
    };
    child_handles.extend([input_read, output_write]);
    let inherit: Vec<_> = child_handles.iter().map(raw).collect();
    if size.is_none() {
        unsafe {
            attributes.set(
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                inherit.as_ptr().cast(),
                size_of_val(&inherit[..]),
            )?;
        }
    }
    let mut information = PROCESS_INFORMATION::default();
    let mut flags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT;
    if size.is_none() {
        flags |= CREATE_NO_WINDOW;
    }
    if let Err(error) = cancel.check() {
        readers.clear();
        drop(pty);
        return Err(error.context("before CreateProcessW"));
    }
    let launch = unsafe {
        CreateProcessW(
            PCWSTR(program.as_ptr()),
            Some(PWSTR(command.as_mut_ptr())),
            None,
            None,
            size.is_none(),
            flags,
            Some(env.as_ptr().cast()),
            PCWSTR(cwd_wide.as_ptr()),
            &startup.StartupInfo,
            &mut information,
        )
    };
    if let Err(error) = launch {
        readers.clear();
        drop(pty);
        return Err(
            anyhow::Error::from(error).context("CreateProcessW (no process has been resumed)")
        );
    }
    let process = unsafe { own(information.hProcess) };
    let thread = unsafe { own(information.hThread) };
    let prepare = (|| -> anyhow::Result<(u64, String)> {
        unsafe { AssignProcessToJobObject(raw(&job), raw(&process)) }
            .context("cannot establish owned process tree before resume")?;
        let creation_time = process_creation_time(raw(&process))?;
        let mut image = vec![0u16; 32768];
        let mut length = image.len() as u32;
        unsafe {
            QueryFullProcessImageNameW(
                raw(&process),
                PROCESS_NAME_FORMAT(0),
                PWSTR(image.as_mut_ptr()),
                &mut length,
            )?;
        }
        Ok((
            creation_time,
            String::from_utf16(&image[..length as usize])?,
        ))
    })();
    let (creation_time, image) = match prepare {
        Ok(value) => value,
        Err(error) => {
            let cleanup = unsafe { TerminateProcess(raw(&process), CANCEL_EXIT_CODE) };
            readers.clear();
            drop(pty);
            if let Err(cleanup) = cleanup {
                return Err(error.context(format!(
                    "also failed to terminate suspended process: {cleanup}"
                )));
            }
            return Err(error);
        }
    };
    drop(child_handles);
    let created = CreatedProcess {
        process: Arc::new(NativeProcess {
            process,
            job,
            pty: Mutex::new(pty),
            pid: information.dwProcessId,
            creation_time,
            program: image,
            cwd: cwd.to_string_lossy().into_owned(),
        }),
        thread: Some(thread),
        stdin: Some(File::from(input_write)),
        readers,
    };
    #[cfg(test)]
    cancel.pause(
        super::tests::StartupPhase::NativeCreated,
        Some(&created.process),
    )?;
    cancel
        .check()
        .context("after CreateProcessW; suspended child has been terminated")?;
    Ok(created)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executable_resolution_uses_child_path_and_selected_cwd() -> anyhow::Result<()> {
        let directory = std::env::temp_dir().join(format!("mcp-path-{}", uuid::Uuid::new_v4()));
        let tools = directory.join("tools");
        std::fs::create_dir(&directory)?;
        std::fs::create_dir(&tools)?;
        let name = format!("probe-{}", uuid::Uuid::new_v4());
        let executable = tools.join(format!("{name}.exe"));
        std::fs::write(&executable, b"resolver fixture, never executed")?;
        let (_, path) = environment(&BTreeMap::from([("pAtH".into(), Some("tools".into()))]))?;
        let found = resolve_program(
            &name,
            &directory,
            path.as_ref(),
            &StartupCancellation::default(),
        )?;
        assert_eq!(
            PathBuf::from(OsString::from_wide(&found[..found.len() - 1])),
            executable
        );
        let found = resolve_program(
            &format!("tools\\{name}"),
            &directory,
            None,
            &StartupCancellation::default(),
        )?;
        assert_eq!(
            PathBuf::from(OsString::from_wide(&found[..found.len() - 1])),
            executable
        );
        let (_, cleared) = environment(&BTreeMap::from([("PATH".into(), None)]))?;
        assert!(cleared.is_none());
        std::fs::remove_file(executable)?;
        std::fs::remove_dir(tools)?;
        std::fs::remove_dir(directory)?;
        Ok(())
    }
}

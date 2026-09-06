use std::collections::{BTreeMap, HashSet};
use std::ffi::c_void;
use std::sync::{Mutex, MutexGuard, TryLockError};
use std::time::Duration;

use anyhow::{bail, Result};
use serde::Serialize;
use windows::core::w;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::*;
use windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_I386;
use windows::Win32::System::Threading::*;

use super::native::{native_error, open_thread, thread_ids, Deadline, Process, ProcessIdentity};
use super::StacksInput;

static DBGHELP: Mutex<()> = Mutex::new(());

pub(super) fn dbghelp_lock(deadline: &Deadline) -> Result<MutexGuard<'static, ()>> {
    loop {
        deadline.check()?;
        match DBGHELP.try_lock() {
            Ok(lock) => return Ok(lock),
            Err(TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(5)),
            Err(TryLockError::Poisoned(_)) => bail!("DbgHelp serialization lock poisoned"),
        }
    }
}

struct Symbols {
    process: HANDLE,
    previous_options: u32,
}

impl Symbols {
    fn new(process: HANDLE) -> Result<Self> {
        // Ignore environment search paths and CodeView PDB paths: stack capture
        // must not start a network symbol download while a target is suspended.
        let previous_options = unsafe {
            SymSetOptions(
                SYMOPT_DEFERRED_LOADS
                    | SYMOPT_UNDNAME
                    | SYMOPT_NO_PROMPTS
                    | SYMOPT_FAIL_CRITICAL_ERRORS
                    | SYMOPT_IGNORE_NT_SYMPATH
                    | SYMOPT_NO_IMAGE_SEARCH
                    | SYMOPT_IGNORE_CVREC,
            )
        };
        if let Err(error) = unsafe { SymInitializeW(process, w!(""), true) } {
            unsafe {
                SymSetOptions(previous_options);
            }
            return Err(native_error("SymInitializeW", error));
        }
        Ok(Self {
            process,
            previous_options,
        })
    }
}

impl Drop for Symbols {
    fn drop(&mut self) {
        if let Err(error) = unsafe { SymCleanup(self.process) } {
            tracing::error!(%error, "diagnostics SymCleanup failed");
        }
        unsafe {
            SymSetOptions(self.previous_options);
        }
    }
}

struct ResumeOnce<F: FnOnce() -> Result<()>>(Option<F>);

impl<F: FnOnce() -> Result<()>> ResumeOnce<F> {
    fn finish(mut self) -> Result<()> {
        match self.0.take() {
            Some(resume) => resume(),
            None => Ok(()),
        }
    }
}

impl<F: FnOnce() -> Result<()>> Drop for ResumeOnce<F> {
    fn drop(&mut self) {
        if let Some(resume) = self.0.take() {
            if let Err(error) = resume() {
                tracing::error!(%error, "diagnostics thread resume failed");
            }
        }
    }
}

fn suspend(thread: HANDLE) -> Result<(u32, ResumeOnce<impl FnOnce() -> Result<()>>)> {
    let prior = unsafe { SuspendThread(thread) };
    if prior == u32::MAX {
        return Err(native_error(
            "SuspendThread",
            windows::core::Error::from_thread(),
        ));
    }
    // One successful suspend owns exactly one resume, regardless of the prior
    // count. Never undo a suspension established by another debugger.
    Ok((
        prior,
        ResumeOnce(Some(move || {
            if unsafe { ResumeThread(thread) } == u32::MAX {
                Err(native_error(
                    "ResumeThread",
                    windows::core::Error::from_thread(),
                ))
            } else {
                Ok(())
            }
        })),
    ))
}

#[repr(C, align(16))]
pub(super) struct AlignedContext(CONTEXT);

pub(super) enum ThreadContext {
    Native(Box<AlignedContext>),
    #[cfg(target_arch = "x86_64")]
    Wow64(Box<WOW64_CONTEXT>),
}

impl ThreadContext {
    pub fn read(process: &Process, thread: HANDLE) -> Result<Self> {
        process.ensure_context_supported()?;
        #[cfg(target_arch = "x86_64")]
        if process.machine == IMAGE_FILE_MACHINE_I386 {
            let mut context = Box::new(WOW64_CONTEXT {
                ContextFlags: WOW64_CONTEXT_FULL,
                ..Default::default()
            });
            unsafe { Wow64GetThreadContext(thread, context.as_mut()) }
                .map_err(|error| native_error("Wow64GetThreadContext", error))?;
            return Ok(Self::Wow64(context));
        }
        let mut context = Box::new(AlignedContext(CONTEXT::default()));
        #[cfg(target_arch = "x86_64")]
        {
            context.0.ContextFlags = CONTEXT_FULL_AMD64;
        }
        #[cfg(target_arch = "x86")]
        {
            context.0.ContextFlags = CONTEXT_FULL_X86;
        }
        #[cfg(target_arch = "aarch64")]
        {
            context.0.ContextFlags = CONTEXT_FULL_ARM64;
        }
        unsafe { GetThreadContext(thread, &mut context.0) }
            .map_err(|error| native_error("GetThreadContext", error))?;
        Ok(Self::Native(context))
    }

    pub fn registers(&self) -> BTreeMap<String, u64> {
        let mut values = BTreeMap::new();
        macro_rules! registers {
            ($context:expr, $($name:literal => $field:ident),+ $(,)?) => {
                $(values.insert($name.into(), $context.$field as u64);)+
            };
        }
        match self {
            Self::Native(context) => {
                #[cfg(target_arch = "x86_64")]
                registers!(context.0,
                    "rip" => Rip, "rsp" => Rsp, "rbp" => Rbp, "rax" => Rax, "rbx" => Rbx,
                    "rcx" => Rcx, "rdx" => Rdx, "rsi" => Rsi, "rdi" => Rdi,
                    "r8" => R8, "r9" => R9, "r10" => R10, "r11" => R11, "r12" => R12,
                    "r13" => R13, "r14" => R14, "r15" => R15, "eflags" => EFlags);
                #[cfg(target_arch = "x86")]
                registers!(context.0,
                    "eip" => Eip, "esp" => Esp, "ebp" => Ebp, "eax" => Eax, "ebx" => Ebx,
                    "ecx" => Ecx, "edx" => Edx, "esi" => Esi, "edi" => Edi, "eflags" => EFlags);
                #[cfg(target_arch = "aarch64")]
                {
                    registers!(context.0, "pc" => Pc, "sp" => Sp, "cpsr" => Cpsr);
                    for (index, value) in unsafe { context.0.Anonymous.X }.into_iter().enumerate() {
                        values.insert(format!("x{index}"), value);
                    }
                }
            }
            #[cfg(target_arch = "x86_64")]
            Self::Wow64(context) => {
                registers!(context,
                    "eip" => Eip, "esp" => Esp, "ebp" => Ebp, "eax" => Eax, "ebx" => Ebx,
                    "ecx" => Ecx, "edx" => Edx, "esi" => Esi, "edi" => Edi, "eflags" => EFlags);
            }
        }
        values
    }

    fn initial_frame(&self) -> STACKFRAME64 {
        let registers = self.registers();
        let find = |names: &[&str]| {
            names
                .iter()
                .find_map(|name| registers.get(*name))
                .copied()
                .unwrap_or(0)
        };
        STACKFRAME64 {
            AddrPC: ADDRESS64 {
                Offset: find(&["rip", "eip", "pc"]),
                Mode: AddrModeFlat,
                ..Default::default()
            },
            AddrStack: ADDRESS64 {
                Offset: find(&["rsp", "esp", "sp"]),
                Mode: AddrModeFlat,
                ..Default::default()
            },
            AddrFrame: ADDRESS64 {
                Offset: find(&["rbp", "ebp", "x29"]),
                Mode: AddrModeFlat,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn as_mut_ptr(&mut self) -> *mut c_void {
        match self {
            Self::Native(context) => (&mut context.0 as *mut CONTEXT).cast(),
            #[cfg(target_arch = "x86_64")]
            Self::Wow64(context) => (context.as_mut() as *mut WOW64_CONTEXT).cast(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct StackFrame {
    pub pc: String,
    pub stack_pointer: String,
    pub frame_pointer: String,
    pub module_base: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ThreadStack {
    pub thread_id: u32,
    pub creation_time: Option<String>,
    pub prior_suspend_count: Option<u32>,
    pub frames: Vec<StackFrame>,
    pub unwind_status: String,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct StackReport {
    pub target: ProcessIdentity,
    pub threads: Vec<ThreadStack>,
    pub truncated: bool,
    pub partial: bool,
    pub error: Option<String>,
    pub limitations: Vec<String>,
}

unsafe extern "system" fn function_table(process: HANDLE, address: u64) -> *mut c_void {
    unsafe { SymFunctionTableAccess64(process, address) }
}

unsafe extern "system" fn module_base(process: HANDLE, address: u64) -> u64 {
    unsafe { SymGetModuleBase64(process, address) }
}

fn unwind(
    process: &Process,
    thread: HANDLE,
    limit: usize,
    deadline: &Deadline,
) -> Result<(Vec<StackFrame>, String)> {
    let mut context = ThreadContext::read(process, thread)?;
    let mut frame = context.initial_frame();
    let mut frames = Vec::new();
    let mut seen = HashSet::new();
    for _ in 0..limit {
        deadline.check()?;
        let walked = unsafe {
            StackWalk64(
                u32::from(process.machine.0),
                process.handle.0,
                thread,
                &mut frame,
                context.as_mut_ptr(),
                None,
                Some(function_table),
                Some(module_base),
                None,
            )
        };
        if !walked.as_bool() || frame.AddrPC.Offset == 0 {
            return Ok((frames, "end_or_unavailable_unwind_information".into()));
        }
        if !seen.insert((frame.AddrPC.Offset, frame.AddrStack.Offset)) {
            return Ok((frames, "repeated_frame".into()));
        }
        let base = unsafe { SymGetModuleBase64(process.handle.0, frame.AddrPC.Offset) };
        frames.push(StackFrame {
            pc: format!("0x{:x}", frame.AddrPC.Offset),
            stack_pointer: format!("0x{:x}", frame.AddrStack.Offset),
            frame_pointer: format!("0x{:x}", frame.AddrFrame.Offset),
            module_base: (base != 0).then(|| format!("0x{base:x}")),
        });
    }
    Ok((frames, "frame_limit".into()))
}

pub(super) fn capture(input: StacksInput, deadline: Deadline) -> Result<StackReport> {
    let process = Process::open(
        input.target.pid,
        Some(input.target.creation_time),
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
    )?;
    process.ensure_external()?;
    process.ensure_context_supported()?;
    let max_threads = super::bounded(input.max_threads, 32, 1, 256, "max_threads")?;
    let max_frames = super::bounded(input.max_frames, 64, 1, 256, "max_frames")?;
    let (threads, truncated) = match input.thread_id {
        Some(thread) => (vec![thread], false),
        None => thread_ids(&process, max_threads, &deadline)?,
    };
    let _lock = dbghelp_lock(&deadline)?;
    let _symbols = Symbols::new(process.handle.0)?;
    let mut report = StackReport {
        target: process.identity.clone(), threads: Vec::new(), truncated, partial: truncated, error: None,
        limitations: vec![
            "Stacks are sampled one thread at a time, not an atomic process snapshot.".into(),
            "Missing unwind metadata, JIT code, or optimized frames can stop unwinding; addresses are not guaranteed to name every frame.".into(),
            "No PDB download or symbol-server access is performed. Native DbgHelp calls have cooperative deadlines.".into(),
        ],
    };
    for tid in threads {
        if let Err(error) = deadline.check() {
            report.error = Some(error.to_string());
            report.partial = true;
            break;
        }
        let mut row = ThreadStack {
            thread_id: tid,
            creation_time: None,
            prior_suspend_count: None,
            frames: Vec::new(),
            unwind_status: "unavailable".into(),
            error: None,
        };
        let result = (|| -> Result<()> {
            let (thread, creation) =
                open_thread(&process, tid, THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME)?;
            row.creation_time = Some(creation.to_string());
            let (prior, guard) = suspend(thread.0)?;
            row.prior_suspend_count = Some(prior);
            let walked = unwind(&process, thread.0, max_frames, &deadline);
            let resumed = guard.finish();
            if let Err(error) = resumed {
                bail!("thread {tid} resume failed after capture: {error}");
            }
            let (frames, status) = walked?;
            row.frames = frames;
            row.unwind_status = status;
            Ok(())
        })();
        if let Err(error) = result {
            row.error = Some(format!("{error:#}"));
            report.partial = true;
        }
        if row.frames.is_empty()
            || row.unwind_status == "frame_limit"
            || row.unwind_status == "repeated_frame"
        {
            report.partial = true;
        }
        report.threads.push(row);
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn suspension_is_released_once_on_error_and_normal_completion() {
        let resumes = Cell::new(0);
        let action = || {
            resumes.set(resumes.get() + 1);
            Ok(())
        };
        {
            let _guard = ResumeOnce(Some(action));
        }
        assert_eq!(resumes.get(), 1);
        ResumeOnce(Some(action)).finish().unwrap();
        assert_eq!(resumes.get(), 2);
    }

    #[test]
    fn suspension_is_released_on_cancellation_unwind() {
        let resumes = Cell::new(0);
        let result = (|| -> Result<()> {
            let _guard = ResumeOnce(Some(|| {
                resumes.set(resumes.get() + 1);
                Ok(())
            }));
            let deadline = Deadline::new(100)?;
            deadline.cancel();
            deadline.check()?;
            Err(anyhow::anyhow!("unreachable"))
        })();
        assert!(result.is_err());
        assert_eq!(resumes.get(), 1);
    }
}

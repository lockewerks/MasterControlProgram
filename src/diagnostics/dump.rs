use std::fs::{File, OpenOptions};
use std::mem::size_of;
use std::os::windows::fs::{FileExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, Prefix};

use anyhow::{bail, Context, Result};
use serde::Serialize;
use windows::core::BOOL;
use windows::Win32::Foundation::*;
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::Diagnostics::Debug::*;
use windows::Win32::System::Threading::*;

use super::native::{Deadline, Process, ProcessIdentity};
use super::{DumpInput, DumpKind};

#[derive(Debug, Serialize)]
pub struct DumpReport {
    pub target: ProcessIdentity,
    pub path: String,
    pub resolved_path: String,
    pub size_bytes: u64,
    pub requested_flags: u32,
    pub captured_flags: u64,
    pub requested_flag_names: Vec<&'static str>,
    pub complete: bool,
}

struct Writer {
    file: File,
    deadline: Deadline,
    max_bytes: u64,
    error: Option<String>,
}

fn validate_path(path: &Path) -> Result<()> {
    let disk = matches!(path.components().next(),
        Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)));
    if !path.is_absolute() || !disk || path.as_os_str().to_string_lossy().contains('\0') {
        bail!("dump path must be an absolute local drive path, not a network path or device namespace");
    }
    if path.components().any(|component| match component {
        Component::Normal(name) => name.to_string_lossy().contains(':'),
        _ => false,
    }) {
        bail!("dump path cannot use an alternate data stream");
    }
    Ok(())
}

unsafe extern "system" fn callback(
    context: *mut std::ffi::c_void,
    input: *const MINIDUMP_CALLBACK_INPUT,
    output: *mut MINIDUMP_CALLBACK_OUTPUT,
) -> BOOL {
    if context.is_null() || input.is_null() || output.is_null() {
        return false.into();
    }
    let writer = unsafe { &mut *context.cast::<Writer>() };
    let kind = unsafe { (*input).CallbackType };
    if kind == CancelCallback.0 as u32 {
        let canceled = writer.deadline.check().is_err() || writer.error.is_some();
        unsafe {
            (*output).Anonymous.Anonymous2 = MINIDUMP_CALLBACK_OUTPUT_0_1 {
                CheckCancel: true.into(),
                Cancel: canceled.into(),
            };
        }
    } else if kind == IoStartCallback.0 as u32 {
        unsafe {
            (*output).Anonymous.Status = S_FALSE;
        }
    } else if kind == IoWriteAllCallback.0 as u32 {
        let io = unsafe { (*input).Anonymous.Io };
        let result = (|| -> Result<()> {
            writer.deadline.check()?;
            let end = io
                .Offset
                .checked_add(u64::from(io.BufferBytes))
                .context("dump offset overflow")?;
            if end > writer.max_bytes {
                bail!("dump exceeded max_bytes ({})", writer.max_bytes);
            }
            if io.BufferBytes != 0 && io.Buffer.is_null() {
                bail!("DbgHelp supplied an invalid output buffer");
            }
            if u64::from(io.BufferBytes) > isize::MAX as u64 {
                bail!("DbgHelp output buffer exceeds this architecture's slice bound");
            }
            if io.BufferBytes != 0 {
                let bytes = unsafe {
                    std::slice::from_raw_parts(io.Buffer.cast::<u8>(), io.BufferBytes as usize)
                };
                let mut written = 0;
                while written < bytes.len() {
                    writer.deadline.check()?;
                    let count = writer
                        .file
                        .seek_write(&bytes[written..], io.Offset + written as u64)?;
                    if count == 0 {
                        bail!("dump output write made no progress");
                    }
                    written += count;
                }
            }
            Ok(())
        })();
        let status = match result {
            Ok(()) => S_OK,
            Err(error) => {
                if writer.error.is_none() {
                    writer.error = Some(format!("{error:#}"));
                }
                E_ABORT
            }
        };
        unsafe {
            (*output).Anonymous.Status = status;
        }
    } else if kind == IoFinishCallback.0 as u32 {
        unsafe {
            (*output).Anonymous.Status = if writer.error.is_none() {
                S_OK
            } else {
                E_ABORT
            };
        }
    }
    true.into()
}

fn discard(file: &File) -> Result<()> {
    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    unsafe {
        SetFileInformationByHandle(
            HANDLE(file.as_raw_handle()),
            FileDispositionInfo,
            (&info as *const FILE_DISPOSITION_INFO).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    }
    .context("cannot delete incomplete dump through its retained file handle")
}

fn resolve_artifact(file: &File) -> Result<String> {
    let handle = HANDLE(file.as_raw_handle());
    if unsafe { GetFileType(handle) } != FILE_TYPE_DISK {
        bail!("dump artifact is not a regular disk file");
    }
    let mut name = vec![0u16; 32768];
    let length = unsafe { GetFinalPathNameByHandleW(handle, &mut name, FILE_NAME_NORMALIZED) };
    if length == 0 || length as usize >= name.len() {
        bail!("cannot resolve dump artifact's final path");
    }
    let resolved = String::from_utf16_lossy(&name[..length as usize]);
    validate_path(Path::new(&resolved))?;
    Ok(resolved)
}

fn captured_flags(file: &File) -> Result<u64> {
    let mut header = [0u8; 32];
    let mut read = 0;
    while read < header.len() {
        let count = file.seek_read(&mut header[read..], read as u64)?;
        if count == 0 {
            bail!("dump header is incomplete");
        }
        read += count;
    }
    if &header[..4] != b"MDMP" {
        bail!("output has no valid minidump signature");
    }
    Ok(u64::from_le_bytes(
        header[24..32].try_into().expect("fixed header slice"),
    ))
}

pub(super) fn capture(input: DumpInput, deadline: Deadline) -> Result<DumpReport> {
    validate_path(Path::new(&input.path))?;
    let max_bytes = input.max_bytes.unwrap_or(268_435_456);
    if !(1_048_576..=2_147_483_648).contains(&max_bytes) {
        bail!("max_bytes must be between 1048576 and 2147483648");
    }
    let mut access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
    if input.include_handles {
        access |= PROCESS_DUP_HANDLE;
    }
    let process = Process::open(input.target.pid, Some(input.target.creation_time), access)?;
    process.ensure_external()?;
    process.ensure_context_supported()?;
    let _lock = super::stacks::dbghelp_lock(&deadline)?;
    deadline.check()?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(0)
        .access_mode(GENERIC_READ.0 | GENERIC_WRITE.0 | DELETE.0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(&input.path)
        .context("create fresh exclusive dump artifact")?;
    let resolved_path = match resolve_artifact(&file) {
        Ok(path) => path,
        Err(error) => {
            discard(&file).with_context(|| format!("invalid dump artifact: {error:#}"))?;
            return Err(error);
        }
    };
    let mut flags = MiniDumpWithThreadInfo | MiniDumpWithUnloadedModules;
    let mut names = vec!["MiniDumpWithThreadInfo", "MiniDumpWithUnloadedModules"];
    if matches!(input.kind, DumpKind::Full) {
        flags |= MiniDumpWithFullMemory;
        names.push("MiniDumpWithFullMemory");
    }
    if input.include_handles {
        flags |= MiniDumpWithHandleData;
        names.push("MiniDumpWithHandleData");
    }
    let mut writer = Writer {
        file,
        deadline,
        max_bytes,
        error: None,
    };
    let callbacks = MINIDUMP_CALLBACK_INFORMATION {
        CallbackRoutine: Some(callback),
        CallbackParam: (&mut writer as *mut Writer).cast(),
    };
    let captured = unsafe {
        MiniDumpWriteDump(
            process.handle.0,
            process.identity.pid,
            HANDLE(writer.file.as_raw_handle()),
            flags,
            None,
            None,
            Some(&callbacks),
        )
    };
    let result = (|| -> Result<(u64, u64)> {
        if let Some(error) = &writer.error {
            bail!("{error}");
        }
        writer.deadline.check()?;
        captured.context("MiniDumpWriteDump")?;
        writer.file.sync_all().context("flush dump artifact")?;
        let size = writer.file.metadata()?.len();
        if size == 0 || size > max_bytes {
            bail!("dump output size {size} is invalid");
        }
        Ok((size, captured_flags(&writer.file)?))
    })();
    match result {
        Ok((size_bytes, captured_flags)) => Ok(DumpReport {
            target: process.identity,
            path: input.path,
            resolved_path,
            size_bytes,
            requested_flags: flags.0 as u32,
            captured_flags,
            requested_flag_names: names,
            complete: true,
        }),
        Err(error) => {
            if let Err(cleanup) = discard(&writer.file) {
                let size = writer.file.metadata().map(|value| value.len());
                bail!("dump failed: {error:#}; incomplete artifact retained at {} (size {size:?}): {cleanup:#}", input.path);
            }
            bail!("dump failed; incomplete artifact removed: {error:#}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_must_be_local_and_not_a_stream() {
        assert!(validate_path(Path::new(r"C:\temp\dump.dmp")).is_ok());
        for path in [
            r"\\server\share\dump.dmp",
            r"\\.\PhysicalDrive0",
            r"relative.dmp",
            r"C:\temp\dump:stream",
        ] {
            assert!(validate_path(Path::new(path)).is_err(), "{path}");
        }
    }
}

use std::mem::size_of;

use anyhow::Result;
use serde::Serialize;
use windows::Win32::Foundation::ERROR_NO_MORE_ITEMS;
use windows::Win32::System::Diagnostics::ProcessSnapshotting::*;
use windows::Win32::System::Threading::*;

use super::native::{filetime, win32_result, Deadline, Process, ProcessIdentity};
use super::HandlesInput;

struct Snapshot(HPSS);

impl Drop for Snapshot {
    fn drop(&mut self) {
        let code = unsafe { PssFreeSnapshot(GetCurrentProcess(), self.0) };
        if code != 0 {
            tracing::error!(code, "diagnostics PssFreeSnapshot failed");
        }
    }
}

struct Marker(HPSSWALK);

impl Drop for Marker {
    fn drop(&mut self) {
        let code = unsafe { PssWalkMarkerFree(self.0) };
        if code != 0 {
            tracing::error!(code, "diagnostics PssWalkMarkerFree failed");
        }
    }
}

#[derive(Debug, Serialize)]
pub struct HandleEntry {
    pub handle: String,
    pub object_type: &'static str,
    pub information_flags: i32,
    pub captured_at: String,
    pub granted_access: Option<u32>,
    pub attributes: Option<u32>,
    pub handle_count: Option<u32>,
    pub pointer_count: Option<u32>,
    pub related_process_id: Option<u32>,
    pub related_thread_id: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct HandlesReport {
    pub target: ProcessIdentity,
    pub capture_flags: u32,
    pub handles: Vec<HandleEntry>,
    pub total_captured: u32,
    pub partial: bool,
    pub error: Option<String>,
    pub limitations: Vec<String>,
}

pub(super) fn capture(input: HandlesInput, deadline: Deadline) -> Result<HandlesReport> {
    let limit = super::bounded(input.limit, 256, 1, 4096, "limit")?;
    let process = Process::open(
        input.target.pid,
        Some(input.target.creation_time),
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE,
    )?;
    process.ensure_alive()?;
    deadline.check()?;
    let flags = PSS_CAPTURE_HANDLES
        | PSS_CAPTURE_HANDLE_BASIC_INFORMATION
        | PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION;
    let mut snapshot = HPSS::default();
    win32_result("PssCaptureSnapshot", unsafe {
        PssCaptureSnapshot(process.handle.0, flags, None, &mut snapshot)
    })?;
    let snapshot = Snapshot(snapshot);
    let mut count = PSS_HANDLE_INFORMATION::default();
    win32_result("PssQuerySnapshot", unsafe {
        PssQuerySnapshot(
            snapshot.0,
            PSS_QUERY_HANDLE_INFORMATION,
            (&mut count as *mut PSS_HANDLE_INFORMATION).cast(),
            size_of::<PSS_HANDLE_INFORMATION>() as u32,
        )
    })?;
    let mut marker = HPSSWALK::default();
    win32_result("PssWalkMarkerCreate", unsafe {
        PssWalkMarkerCreate(None, &mut marker)
    })?;
    let marker = Marker(marker);
    let mut report = HandlesReport {
        target: process.identity.clone(), capture_flags: flags.0, handles: Vec::new(),
        total_captured: count.HandlesCaptured, partial: false, error: None,
        limitations: vec![
            "PSS captures handle metadata, not object contents. Snapshot handle values must not be closed or reused as local handles.".into(),
            "Object names are not queried because device/file name providers can block indefinitely. Unclassified types are reported as unknown.".into(),
            "PSS capture itself is synchronous and cannot be forcibly canceled; enumeration observes the deadline.".into(),
        ],
    };
    while report.handles.len() < limit {
        if let Err(error) = deadline.check() {
            report.error = Some(error.to_string());
            report.partial = true;
            break;
        }
        let mut entry = PSS_HANDLE_ENTRY::default();
        let bytes = unsafe {
            std::slice::from_raw_parts_mut(
                (&mut entry as *mut PSS_HANDLE_ENTRY).cast::<u8>(),
                size_of::<PSS_HANDLE_ENTRY>(),
            )
        };
        let code = unsafe { PssWalkSnapshot(snapshot.0, PSS_WALK_HANDLES, marker.0, Some(bytes)) };
        if code == ERROR_NO_MORE_ITEMS.0 {
            break;
        }
        if let Err(error) = win32_result("PssWalkSnapshot", code) {
            report.error = Some(error.to_string());
            report.partial = true;
            break;
        }
        let basic = entry.Flags.contains(PSS_HANDLE_HAVE_BASIC_INFORMATION);
        let specific = entry
            .Flags
            .contains(PSS_HANDLE_HAVE_TYPE_SPECIFIC_INFORMATION);
        let mut row = HandleEntry {
            handle: format!("0x{:x}", entry.Handle.0 as usize),
            object_type: match entry.ObjectType {
                PSS_OBJECT_TYPE_PROCESS => "process",
                PSS_OBJECT_TYPE_THREAD => "thread",
                PSS_OBJECT_TYPE_MUTANT => "mutex",
                PSS_OBJECT_TYPE_EVENT => "event",
                PSS_OBJECT_TYPE_SECTION => "section",
                PSS_OBJECT_TYPE_SEMAPHORE => "semaphore",
                _ => "unknown",
            },
            information_flags: entry.Flags.0,
            captured_at: filetime(entry.CaptureTime).to_string(),
            granted_access: basic.then_some(entry.GrantedAccess),
            attributes: basic.then_some(entry.Attributes),
            handle_count: basic.then_some(entry.HandleCount),
            pointer_count: basic.then_some(entry.PointerCount),
            related_process_id: None,
            related_thread_id: None,
        };
        if specific {
            unsafe {
                if entry.ObjectType == PSS_OBJECT_TYPE_PROCESS {
                    row.related_process_id = Some(entry.TypeSpecificInformation.Process.ProcessId);
                } else if entry.ObjectType == PSS_OBJECT_TYPE_THREAD {
                    row.related_process_id = Some(entry.TypeSpecificInformation.Thread.ProcessId);
                    row.related_thread_id = Some(entry.TypeSpecificInformation.Thread.ThreadId);
                }
            }
        }
        report.handles.push(row);
    }
    report.partial |= report.handles.len() < count.HandlesCaptured as usize;
    Ok(report)
}

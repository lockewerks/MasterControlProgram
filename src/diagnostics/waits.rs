use std::cell::UnsafeCell;
use std::ffi::c_void;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{anyhow, Result};
use serde::Serialize;
use windows::core::{BOOL, HRESULT};
use windows::Win32::Foundation::*;
use windows::Win32::System::Diagnostics::Debug::*;
use windows::Win32::System::Threading::*;

use super::native::{
    native_error, open_thread, thread_ids, win32_result, Deadline, Process, ProcessIdentity,
};
use super::WaitChainInput;

#[derive(Debug, Serialize)]
pub struct WaitNode {
    pub object_type: i32,
    pub object_status: i32,
    pub process_id: Option<u32>,
    pub thread_id: Option<u32>,
    pub wait_time_ms: Option<u32>,
    pub context_switches: Option<u32>,
    pub object_name: Option<String>,
    pub alertable: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct ThreadWait {
    pub thread_id: u32,
    pub creation_time: Option<String>,
    pub nodes: Vec<WaitNode>,
    pub cycle_detected: Option<bool>,
    pub partial: bool,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WaitReport {
    pub target: ProcessIdentity,
    pub threads: Vec<ThreadWait>,
    pub truncated: bool,
    pub partial: bool,
    pub error: Option<String>,
    pub limitations: Vec<String>,
}

type WaitChainResult = (u32, Vec<WaitNode>, Option<bool>);

struct WaitBuffer {
    nodes: UnsafeCell<[WAITCHAIN_NODE_INFO; WCT_MAX_NODE_COUNT as usize]>,
    count: UnsafeCell<u32>,
    cycle: UnsafeCell<BOOL>,
    result: Mutex<Option<WaitChainResult>>,
}

struct Session(*mut c_void);

impl Drop for Session {
    fn drop(&mut self) {
        // WCT guarantees callbacks have returned before this returns. The
        // callback context and output buffers must outlive this guard.
        unsafe {
            CloseThreadWaitChainSession(self.0);
        }
    }
}

unsafe extern "system" fn callback(
    _session: *mut c_void,
    context: usize,
    status: u32,
    count: *mut u32,
    nodes: *mut WAITCHAIN_NODE_INFO,
    cycle: *mut BOOL,
) {
    if context == 0 {
        return;
    }
    let context = unsafe { &*(context as *const WaitBuffer) };
    let mut rows = Vec::new();
    let valid = status == ERROR_SUCCESS.0
        || status == ERROR_MORE_DATA.0
        || status == ERROR_TOO_MANY_THREADS.0;
    let length = if valid && !count.is_null() && !nodes.is_null() {
        unsafe { *count }.min(WCT_MAX_NODE_COUNT) as usize
    } else {
        0
    };
    for index in 0..length {
        let node = unsafe { *nodes.add(index) };
        let mut row = WaitNode {
            object_type: node.ObjectType.0,
            object_status: node.ObjectStatus.0,
            process_id: None,
            thread_id: None,
            wait_time_ms: None,
            context_switches: None,
            object_name: None,
            alertable: None,
        };
        if node.ObjectType == WctThreadType {
            let thread = unsafe { node.Anonymous.ThreadObject };
            row.process_id = Some(thread.ProcessId);
            row.thread_id = Some(thread.ThreadId);
            row.wait_time_ms = Some(thread.WaitTime);
            row.context_switches = Some(thread.ContextSwitches);
        } else {
            let lock = unsafe { node.Anonymous.LockObject };
            let length = lock
                .ObjectName
                .iter()
                .position(|v| *v == 0)
                .unwrap_or(lock.ObjectName.len());
            row.object_name = Some(String::from_utf16_lossy(&lock.ObjectName[..length]));
            row.alertable = Some(lock.Alertable.as_bool());
        }
        rows.push(row);
    }
    let cycle = if valid && !cycle.is_null() {
        Some(unsafe { *cycle }.as_bool())
    } else {
        None
    };
    match context.result.lock() {
        Ok(mut result) => *result = Some((status, rows, cycle)),
        Err(_) => tracing::error!("diagnostics WCT callback result lock poisoned"),
    }
}

fn thread_wait(
    process: &Process,
    tid: u32,
    follow: bool,
    deadline: &Deadline,
) -> Result<ThreadWait> {
    let (_thread, created) = open_thread(process, tid, THREAD_ACCESS_RIGHTS(0))?;
    let buffers = Box::new(WaitBuffer {
        nodes: UnsafeCell::new([WAITCHAIN_NODE_INFO::default(); WCT_MAX_NODE_COUNT as usize]),
        count: UnsafeCell::new(WCT_MAX_NODE_COUNT),
        cycle: UnsafeCell::new(BOOL::default()),
        result: Mutex::new(None),
    });
    let session = unsafe { OpenThreadWaitChainSession(WCT_ASYNC_OPEN_FLAG, Some(callback)) };
    if session.is_null() {
        return Err(native_error(
            "OpenThreadWaitChainSession",
            windows::core::Error::from_thread(),
        ));
    }
    let session = Session(session);
    let started = unsafe {
        GetThreadWaitChain(
            session.0,
            Some((&*buffers as *const WaitBuffer) as usize),
            if follow {
                WCT_OUT_OF_PROC_FLAG
            } else {
                WAIT_CHAIN_THREAD_OPTIONS(0)
            },
            tid,
            buffers.count.get(),
            buffers.nodes.get().cast(),
            buffers.cycle.get(),
        )
    };
    if let Err(error) = started {
        if error.code() != HRESULT::from_win32(ERROR_IO_PENDING.0) {
            return Err(native_error("GetThreadWaitChain", error));
        }
    }
    let result = loop {
        deadline.check()?;
        if let Some(result) = buffers
            .result
            .lock()
            .map_err(|_| anyhow!("WCT result lock poisoned"))?
            .take()
        {
            break result;
        }
        std::thread::sleep(Duration::from_millis(5).min(deadline.remaining()));
    };
    drop(session);
    let (status, nodes, cycle) = result;
    let error = win32_result("GetThreadWaitChain callback", status)
        .err()
        .map(|error| error.to_string());
    let partial = status != 0
        || nodes.iter().any(|node| {
            node.object_status == WctStatusNoAccess.0
                || node.object_status == WctStatusError.0
                || node.object_status == WctStatusPidOnly.0
                || node.object_status == WctStatusPidOnlyRpcss.0
        });
    Ok(ThreadWait {
        thread_id: tid,
        creation_time: Some(created.to_string()),
        nodes,
        cycle_detected: cycle,
        partial,
        error,
    })
}

pub(super) fn capture(input: WaitChainInput, deadline: Deadline) -> Result<WaitReport> {
    let max_threads = super::bounded(input.max_threads, 32, 1, 256, "max_threads")?;
    let process = Process::open(
        input.target.pid,
        Some(input.target.creation_time),
        PROCESS_ACCESS_RIGHTS(0),
    )?;
    let (threads, truncated) = match input.thread_id {
        Some(tid) => (vec![tid], false),
        None => thread_ids(&process, max_threads, &deadline)?,
    };
    let mut report = WaitReport {
        target: process.identity.clone(), threads: Vec::new(), truncated, partial: truncated, error: None,
        limitations: vec![
            "WCT reports observed wait relationships, not proof of an application's failure cause.".into(),
            "At most 16 nodes per chain. COM-specific callbacks are not registered; some COM ownership and protected-process nodes may be unresolved.".into(),
        ],
    };
    for tid in threads {
        if let Err(error) = deadline.check() {
            report.error = Some(error.to_string());
            report.partial = true;
            break;
        }
        match thread_wait(&process, tid, input.follow_owners, &deadline) {
            Ok(row) => {
                report.partial |= row.partial;
                report.threads.push(row);
            }
            Err(error) => {
                report.partial = true;
                report.threads.push(ThreadWait {
                    thread_id: tid,
                    creation_time: None,
                    nodes: Vec::new(),
                    cycle_detected: None,
                    partial: true,
                    error: Some(format!("{error:#}")),
                });
            }
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncated_wct_status_preserves_available_nodes() {
        let buffers = WaitBuffer {
            nodes: UnsafeCell::new([WAITCHAIN_NODE_INFO::default(); WCT_MAX_NODE_COUNT as usize]),
            count: UnsafeCell::new(WCT_MAX_NODE_COUNT + 1),
            cycle: UnsafeCell::new(false.into()),
            result: Mutex::new(None),
        };
        unsafe {
            callback(
                std::ptr::null_mut(),
                (&buffers as *const WaitBuffer) as usize,
                ERROR_TOO_MANY_THREADS.0,
                buffers.count.get(),
                buffers.nodes.get().cast(),
                buffers.cycle.get(),
            );
        }
        let (status, nodes, cycle) = buffers.result.lock().unwrap().take().unwrap();
        assert_eq!(status, ERROR_TOO_MANY_THREADS.0);
        assert_eq!(nodes.len(), WCT_MAX_NODE_COUNT as usize);
        assert_eq!(cycle, Some(false));
    }
}

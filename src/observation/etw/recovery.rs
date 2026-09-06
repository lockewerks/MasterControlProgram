use std::sync::Arc;

use anyhow::{ensure, Context};
use serde::{Deserialize, Serialize};
use windows::{
    core::{GUID, HRESULT, PCWSTR},
    Win32::{
        Foundation::*,
        System::{Diagnostics::Etw::*, Threading::*},
    },
};

use crate::observation::{native, now_ms, ProcessIdentity};

const MAX_ENTRIES: usize = 1024;
const MAX_ENTRY_BYTES: usize = 8192;

#[derive(Clone, Debug, Deserialize, Serialize)]
struct OwnedTrace {
    version: u32,
    watch_id: String,
    session_name: String,
    session_guid: String,
    controller: ProcessIdentity,
    registered_at_unix_ms: u64,
}

impl OwnedTrace {
    fn validate(&self) -> anyhow::Result<()> {
        let id = uuid::Uuid::parse_str(&self.watch_id)?;
        ensure!(
            self.version == 1
                && self.watch_id == id.to_string()
                && self.session_guid == self.watch_id
                && self.session_name == format!("MasterControlProgram-{}", self.watch_id)
                && self.controller.pid != 0
                && self
                    .controller
                    .process_created_100ns
                    .is_some_and(|created| created != 0)
                && self.controller.identity_error.is_none(),
            "invalid exact ETW ownership record"
        );
        Ok(())
    }

    fn filename(&self) -> String {
        format!("trace-{}.json", self.watch_id)
    }

    fn guid(&self) -> anyhow::Result<GUID> {
        Ok(GUID::from_u128(
            uuid::Uuid::parse_str(&self.session_guid)?.as_u128(),
        ))
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct RecoveredTrace {
    pub watch_id: String,
    pub session_name: String,
    pub controller: ProcessIdentity,
    pub session_was_present: bool,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct RecoveryReport {
    pub completed_at_unix_ms: Option<u64>,
    pub live_controllers: usize,
    pub cleaned: Vec<RecoveredTrace>,
    pub errors: Vec<String>,
}

trait JournalStore: Send + Sync {
    fn entries(&self) -> anyhow::Result<Vec<String>>;
    fn read(&self, name: &str) -> anyhow::Result<Option<Vec<u8>>>;
    fn write(&self, name: &str, bytes: &[u8]) -> anyhow::Result<()>;
    fn remove(&self, name: &str) -> anyhow::Result<()>;
}

impl JournalStore for crate::context::RecoveryStore {
    fn entries(&self) -> anyhow::Result<Vec<String>> {
        self.list("trace-")
    }

    fn read(&self, name: &str) -> anyhow::Result<Option<Vec<u8>>> {
        self.read_checkpoint(name, MAX_ENTRY_BYTES)
    }

    fn write(&self, name: &str, bytes: &[u8]) -> anyhow::Result<()> {
        self.write_checkpoint(name, bytes)
    }

    fn remove(&self, name: &str) -> anyhow::Result<()> {
        self.remove_checkpoint(name).map(|_| ())
    }
}

#[derive(Clone)]
pub(super) struct Ownership {
    store: Arc<dyn JournalStore>,
    record: OwnedTrace,
}

impl Ownership {
    pub(super) fn prepare(watch_id: &str) -> anyhow::Result<Self> {
        let store = Arc::new(crate::context::RecoveryStore::open("etw")?);
        let report = recover_store(&*store, controller_running, stop_owned_session)?;
        ensure!(
            report.errors.is_empty(),
            "owned ETW recovery is incomplete: {}",
            report.errors.join("; ")
        );
        Self::register(
            store,
            watch_id,
            native::query_identity(std::process::id(), None)?,
        )
    }

    fn register(
        store: Arc<dyn JournalStore>,
        watch_id: &str,
        controller: ProcessIdentity,
    ) -> anyhow::Result<Self> {
        let record = OwnedTrace {
            version: 1,
            watch_id: watch_id.into(),
            session_name: format!("MasterControlProgram-{watch_id}"),
            session_guid: watch_id.into(),
            controller,
            registered_at_unix_ms: now_ms(),
        };
        record.validate()?;
        let bytes = serde_json::to_vec(&record)?;
        ensure!(
            bytes.len() <= MAX_ENTRY_BYTES,
            "ETW ownership record exceeds its byte limit"
        );
        store
            .write(&record.filename(), &bytes)
            .context("persisting ETW ownership before StartTraceW")?;
        Ok(Self { store, record })
    }

    pub(super) fn guid(&self) -> anyhow::Result<GUID> {
        self.record.guid()
    }

    pub(super) fn clear(&self) -> anyhow::Result<()> {
        self.store
            .remove(&self.record.filename())
            .context("removing stopped ETW ownership record")
    }
}

pub(super) fn recover() -> anyhow::Result<RecoveryReport> {
    let store = crate::context::RecoveryStore::open("etw")?;
    recover_store(&store, controller_running, stop_owned_session)
}

fn recover_store(
    store: &dyn JournalStore,
    running: impl FnMut(&ProcessIdentity) -> anyhow::Result<bool>,
    stop: impl FnMut(&OwnedTrace) -> anyhow::Result<bool>,
) -> anyhow::Result<RecoveryReport> {
    recover_entries(store, store.entries()?, running, stop)
}

fn recover_entries(
    store: &dyn JournalStore,
    mut entries: Vec<String>,
    mut running: impl FnMut(&ProcessIdentity) -> anyhow::Result<bool>,
    mut stop: impl FnMut(&OwnedTrace) -> anyhow::Result<bool>,
) -> anyhow::Result<RecoveryReport> {
    ensure!(
        entries.len() <= MAX_ENTRIES,
        "ETW recovery entry limit exceeded"
    );
    entries.sort();
    let mut report = RecoveryReport::default();
    for filename in entries {
        let result = (|| -> anyhow::Result<()> {
            let Some(bytes) = store.read(&filename)? else {
                return Ok(());
            };
            ensure!(
                bytes.len() <= MAX_ENTRY_BYTES,
                "ETW recovery entry exceeds its byte limit"
            );
            let record: OwnedTrace =
                serde_json::from_slice(&bytes).context("invalid ETW ownership JSON")?;
            record.validate()?;
            ensure!(
                filename == record.filename(),
                "ETW ownership filename does not match its exact session"
            );
            if running(&record.controller)? {
                report.live_controllers += 1;
                return Ok(());
            }
            let session_was_present = stop(&record)?;
            store.remove(&filename)?;
            report.cleaned.push(RecoveredTrace {
                watch_id: record.watch_id,
                session_name: record.session_name,
                controller: record.controller,
                session_was_present,
            });
            Ok(())
        })();
        if let Err(error) = result {
            report.errors.push(
                format!("{filename}: {error:#}")
                    .chars()
                    .take(2048)
                    .collect(),
            );
        }
    }
    report.completed_at_unix_ms = Some(now_ms());
    Ok(report)
}

fn controller_running(identity: &ProcessIdentity) -> anyhow::Result<bool> {
    let process = match unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            false,
            identity.pid,
        )
    } {
        Ok(handle) => unsafe { native::Handle::from_handle(handle) },
        Err(error) if error.code() == HRESULT::from_win32(ERROR_INVALID_PARAMETER.0) => {
            return Ok(false)
        }
        Err(error) => return Err(error).context("opening the recorded ETW controller identity"),
    };
    let creation = crate::context::process_creation_time(process.raw())?;
    if Some(creation) != identity.process_created_100ns {
        return Ok(false);
    }
    match unsafe { WaitForSingleObject(process.raw(), 0) } {
        WAIT_TIMEOUT => Ok(true),
        WAIT_OBJECT_0 => Ok(false),
        result => anyhow::bail!("querying the ETW controller's exit state failed: {result:?}"),
    }
}

fn stop_owned_session(record: &OwnedTrace) -> anyhow::Result<bool> {
    let name = native::wide(&record.session_name);
    let mut properties = super::Properties::new(&name);
    let code = unsafe {
        ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            PCWSTR(name.as_ptr()),
            &mut properties.properties,
            EVENT_TRACE_CONTROL_QUERY,
        )
    };
    if code == ERROR_WMI_INSTANCE_NOT_FOUND {
        return Ok(false);
    }
    native::win32(code, "querying exact orphaned ETW session")?;
    ensure!(
        properties.properties.Wnode.Guid == record.guid()?,
        "ETW session name now belongs to a different session GUID; refusing to stop it"
    );
    let code = unsafe {
        ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            PCWSTR(name.as_ptr()),
            &mut properties.properties,
            EVENT_TRACE_CONTROL_STOP,
        )
    };
    ensure!(
        stopped(code),
        "stopping exact orphaned ETW session failed: Win32 {}",
        code.0
    );
    Ok(true)
}

pub(super) fn stopped(code: WIN32_ERROR) -> bool {
    matches!(
        code,
        ERROR_SUCCESS | ERROR_MORE_DATA | ERROR_WMI_INSTANCE_NOT_FOUND
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observation::{test_support::MemoryCheckpoint, CheckpointStore};
    use std::sync::atomic::Ordering;

    impl JournalStore for MemoryCheckpoint {
        fn entries(&self) -> anyhow::Result<Vec<String>> {
            Ok(self.bytes.lock().unwrap().keys().cloned().collect())
        }
        fn read(&self, name: &str) -> anyhow::Result<Option<Vec<u8>>> {
            self.read_checkpoint(name, MAX_ENTRY_BYTES)
        }
        fn write(&self, name: &str, bytes: &[u8]) -> anyhow::Result<()> {
            self.write_checkpoint(name, bytes)
        }
        fn remove(&self, name: &str) -> anyhow::Result<()> {
            self.bytes.lock().unwrap().remove(name);
            Ok(())
        }
    }

    fn fixture(store: Arc<MemoryCheckpoint>) -> Ownership {
        Ownership::register(
            store,
            &uuid::Uuid::new_v4().to_string(),
            ProcessIdentity {
                pid: 123,
                process_created_100ns: Some(456),
                session_id: Some(1),
                identity_error: None,
            },
        )
        .unwrap()
    }

    #[test]
    fn ownership_is_persisted_before_native_start_and_write_failure_is_fatal() {
        let store = Arc::new(MemoryCheckpoint::default());
        let ownership = fixture(store.clone());
        let bytes = store.read(&ownership.record.filename()).unwrap().unwrap();
        let saved: OwnedTrace = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(saved.session_name, ownership.record.session_name);
        assert_eq!(saved.controller.process_created_100ns, Some(456));
        ownership.clear().unwrap();
        assert!(store.bytes.lock().unwrap().is_empty());
        store.fail_writes.store(true, Ordering::Release);
        assert!(
            Ownership::register(store, &uuid::Uuid::new_v4().to_string(), saved.controller)
                .is_err()
        );
    }

    #[test]
    fn recovery_skips_live_controllers_and_retries_failed_cleanup_without_replaying() {
        let store = Arc::new(MemoryCheckpoint::default());
        let ownership = fixture(store.clone());
        let mut stop_calls = 0;
        let report = recover_store(
            &*store,
            |_| Ok(true),
            |_| {
                stop_calls += 1;
                Ok(true)
            },
        )
        .unwrap();
        assert_eq!(report.live_controllers, 1);
        assert_eq!(stop_calls, 0);
        let report = recover_store(
            &*store,
            |_| Ok(false),
            |record| {
                assert_eq!(record.session_guid, ownership.record.session_guid);
                anyhow::bail!("fixture access denied");
            },
        )
        .unwrap();
        assert_eq!(report.errors.len(), 1);
        assert_eq!(store.bytes.lock().unwrap().len(), 1);
        let report = recover_store(&*store, |_| Ok(false), |_| Ok(false)).unwrap();
        assert_eq!(report.cleaned.len(), 1);
        assert!(!report.cleaned[0].session_was_present);
        assert!(store.bytes.lock().unwrap().is_empty());
    }

    #[test]
    fn corrupt_ownership_and_unknown_controller_identity_never_stop_sessions() {
        let store = Arc::new(MemoryCheckpoint::default());
        let ownership = fixture(store.clone());
        let report = recover_store(
            &*store,
            |_| anyhow::bail!("fixture identity inaccessible"),
            |_| panic!("inaccessible controller must not be assumed dead"),
        )
        .unwrap();
        assert_eq!(report.errors.len(), 1);
        let mut invalid = ownership.record.clone();
        invalid.session_name = "an-unrelated-session".into();
        store
            .write(
                &ownership.record.filename(),
                &serde_json::to_vec(&invalid).unwrap(),
            )
            .unwrap();
        let report = recover_store(
            &*store,
            |_| panic!("validate ownership first"),
            |_| panic!("malformed ownership must not stop anything"),
        )
        .unwrap();
        assert_eq!(report.errors.len(), 1);
        assert_eq!(store.bytes.lock().unwrap().len(), 1);
    }

    #[test]
    fn controller_identity_detects_pid_reuse_and_stop_accepts_truncated_statistics() {
        let mut identity = native::query_identity(std::process::id(), None).unwrap();
        assert!(controller_running(&identity).unwrap());
        identity.process_created_100ns = Some(identity.process_created_100ns.unwrap() + 1);
        assert!(!controller_running(&identity).unwrap());
        assert!(stopped(ERROR_MORE_DATA));
        assert!(stopped(ERROR_WMI_INSTANCE_NOT_FOUND));
        assert!(!stopped(ERROR_ACCESS_DENIED));
    }

    struct OrphanFixture {
        child: crate::observation::test_support::ChildFixture,
        store: crate::context::RecoveryStore,
        filename: String,
    }

    impl Drop for OrphanFixture {
        fn drop(&mut self) {
            let cleanup = self.child.stop().and_then(|_| {
                let report = recover_entries(
                    &self.store,
                    vec![self.filename.clone()],
                    controller_running,
                    stop_owned_session,
                )?;
                ensure!(report.errors.is_empty(), "{}", report.errors.join("; "));
                Ok(())
            });
            if let Err(error) = cleanup {
                eprintln!(
                    "orphan fixture cleanup failed, retaining native ownership journal: {error:#}"
                );
            }
        }
    }

    #[test]
    #[ignore = "controller subprocess launched only by the native ETW recovery fixture"]
    fn trace_controller_fixture() {
        use std::io::Read;
        let watch_id = match std::env::var("MCP_ETW_FIXTURE_GUID") {
            Ok(watch_id) => watch_id,
            Err(std::env::VarError::NotPresent) => return,
            Err(error) => panic!("invalid ETW fixture identity: {error}"),
        };
        let ready_name = native::wide(&std::env::var("MCP_ETW_FIXTURE_READY").unwrap());
        let ready = unsafe {
            native::Handle::from_handle(
                OpenEventW(EVENT_MODIFY_STATE, false, PCWSTR(ready_name.as_ptr())).unwrap(),
            )
        };
        let ownership = Ownership::register(
            Arc::new(crate::context::RecoveryStore::open("etw").unwrap()),
            &watch_id,
            native::query_identity(std::process::id(), None).unwrap(),
        )
        .unwrap();
        let name = native::wide(&ownership.record.session_name);
        let mut properties = super::super::Properties::new(&name);
        properties.properties.Wnode.Guid = ownership.guid().unwrap();
        let mut handle = CONTROLTRACE_HANDLE::default();
        let code = unsafe {
            StartTraceW(
                &mut handle,
                PCWSTR(name.as_ptr()),
                &mut properties.properties,
            )
        };
        std::fs::write(
            std::env::var_os("MCP_ETW_FIXTURE_STATUS").unwrap(),
            code.0.to_string(),
        )
        .unwrap();
        unsafe {
            SetEvent(ready.raw()).unwrap();
        }
        if code != ERROR_SUCCESS {
            ownership.clear().unwrap();
            return;
        }
        // No Session drop guard: the parent terminates this controller to test
        // an actual surviving logger, rather than simulating a restart flag.
        let bytes = std::io::stdin().read(&mut [0u8]).unwrap();
        assert!(bytes <= 1);
    }

    #[test]
    fn crashed_controller_leaves_a_logger_that_exact_journal_recovery_stops() {
        use crate::observation::test_support::{ChildFixture, FixtureDirectory};
        use std::{
            os::windows::io::AsRawHandle,
            process::{Command, Stdio},
        };
        let directory = FixtureDirectory::new();
        let watch_id = uuid::Uuid::new_v4().to_string();
        let ready_name = format!("Local\\MCP-etw-fixture-{watch_id}");
        let wide_ready = native::wide(&ready_name);
        let ready = unsafe {
            native::Handle::from_handle(
                CreateEventW(None, true, false, PCWSTR(wide_ready.as_ptr())).unwrap(),
            )
        };
        let status = directory.path.join("startup.txt");
        let store = crate::context::RecoveryStore::open("etw").unwrap();
        let child = ChildFixture(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "observation::etw::recovery::tests::trace_controller_fixture",
                    "--nocapture",
                ])
                .env("MCP_ETW_FIXTURE_GUID", &watch_id)
                .env("MCP_ETW_FIXTURE_READY", &ready_name)
                .env("MCP_ETW_FIXTURE_STATUS", &status)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let mut fixture = OrphanFixture {
            child,
            store,
            filename: format!("trace-{watch_id}.json"),
        };
        let signaled = unsafe {
            WaitForMultipleObjects(
                &[ready.raw(), HANDLE(fixture.child.0.as_raw_handle())],
                false,
                10000,
            )
        };
        assert_eq!(
            signaled, WAIT_OBJECT_0,
            "ETW fixture failed before readiness"
        );
        let code: u32 = std::fs::read_to_string(&status).unwrap().parse().unwrap();
        if code != ERROR_SUCCESS.0 {
            eprintln!("native orphan recovery prerequisite unavailable: StartTraceW Win32 {code}");
            return;
        }
        let live = recover_entries(
            &fixture.store,
            vec![fixture.filename.clone()],
            controller_running,
            stop_owned_session,
        )
        .unwrap();
        assert_eq!(live.live_controllers, 1);
        assert!(live.cleaned.is_empty() && live.errors.is_empty());
        fixture.child.0.kill().unwrap();
        fixture.child.0.wait().unwrap();
        let recovered = recover_entries(
            &fixture.store,
            vec![fixture.filename.clone()],
            controller_running,
            stop_owned_session,
        )
        .unwrap();
        assert!(recovered.errors.is_empty(), "{:?}", recovered.errors);
        assert_eq!(recovered.cleaned.len(), 1);
        assert!(recovered.cleaned[0].session_was_present);
        assert!(fixture
            .store
            .read_checkpoint(&fixture.filename, MAX_ENTRY_BYTES)
            .unwrap()
            .is_none());
    }
}

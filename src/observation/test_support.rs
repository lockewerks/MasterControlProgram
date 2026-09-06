use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
};

use anyhow::ensure;

use super::CheckpointStore;

#[derive(Default)]
pub(crate) struct MemoryCheckpoint {
    pub(crate) bytes: Mutex<BTreeMap<String, Vec<u8>>>,
    pub(crate) fail_writes: AtomicBool,
}

impl CheckpointStore for MemoryCheckpoint {
    fn read_checkpoint(&self, name: &str, max_bytes: usize) -> anyhow::Result<Option<Vec<u8>>> {
        let bytes = self.bytes.lock().unwrap().get(name).cloned();
        ensure!(
            bytes.as_ref().is_none_or(|bytes| bytes.len() <= max_bytes),
            "checkpoint exceeds fixture limit"
        );
        Ok(bytes)
    }

    fn write_checkpoint(&self, name: &str, data: &[u8]) -> anyhow::Result<()> {
        ensure!(
            !self.fail_writes.load(Ordering::Acquire),
            "fixture checkpoint write failure"
        );
        self.bytes
            .lock()
            .unwrap()
            .insert(name.into(), data.to_vec());
        Ok(())
    }
}

pub(crate) struct FixtureDirectory {
    pub(crate) path: PathBuf,
}

impl FixtureDirectory {
    pub(crate) fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("MCP-observation-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        Self { path }
    }
}

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.path) {
            assert!(
                std::thread::panicking(),
                "removing fixture {}: {error}",
                self.path.display()
            );
            eprintln!("removing fixture {}: {error}", self.path.display());
        }
    }
}

pub(crate) struct ChildFixture(pub(crate) std::process::Child);

impl ChildFixture {
    pub(crate) fn stop(&mut self) -> anyhow::Result<()> {
        self.0.stdin.take();
        if self.0.try_wait()?.is_none() {
            if let Err(error) = self.0.kill() {
                if self.0.try_wait()?.is_none() {
                    return Err(error.into());
                }
            }
            self.0.wait()?;
        }
        Ok(())
    }
}

impl Drop for ChildFixture {
    fn drop(&mut self) {
        if let Err(error) = self.stop() {
            eprintln!("stopping owned process fixture: {error:#}");
        }
    }
}

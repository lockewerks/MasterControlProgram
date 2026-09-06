use std::{
    fs::File,
    io::{Read, Write},
    os::windows::io::{AsRawHandle, BorrowedHandle},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::JoinHandle,
};

use anyhow::Context;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::windows::named_pipe::NamedPipeClient,
    sync::{mpsc, oneshot},
};
use windows::Win32::{
    Foundation::{ERROR_NOT_FOUND, HANDLE},
    System::{
        Console::{GetStdHandle, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE},
        IO::CancelSynchronousIo,
    },
};

struct StdioThread {
    handle: JoinHandle<()>,
    stop: Arc<AtomicBool>,
}

impl Drop for StdioThread {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Err(error) = unsafe { CancelSynchronousIo(HANDLE(self.handle.as_raw_handle())) } {
            if error.code() != ERROR_NOT_FOUND.to_hresult() {
                tracing::warn!(%error, "stdio bridge I/O cancellation failed");
            }
        }
    }
}

pub(super) async fn relay(pipe: NamedPipeClient) -> anyhow::Result<()> {
    let stdin = unsafe { GetStdHandle(STD_INPUT_HANDLE)? };
    let stdout = unsafe { GetStdHandle(STD_OUTPUT_HANDLE)? };
    anyhow::ensure!(
        !stdin.is_invalid() && !stdout.is_invalid(),
        "stdio bridge requires stdin and stdout handles"
    );
    let mut stdin =
        File::from(unsafe { BorrowedHandle::borrow_raw(stdin.0) }.try_clone_to_owned()?);
    let mut stdout =
        File::from(unsafe { BorrowedHandle::borrow_raw(stdout.0) }.try_clone_to_owned()?);
    let (input_send, mut input_receive) = mpsc::channel::<std::io::Result<Vec<u8>>>(8);
    let input_stop = Arc::new(AtomicBool::new(false));
    let reader_stop = input_stop.clone();
    // Dedicated cancellable threads avoid Tokio's uninterruptible global stdin task
    // keeping a bridge alive after its host has closed the output side.
    let input_thread = StdioThread {
        handle: std::thread::Builder::new()
            .name("mcp-bridge-stdin".into())
            .spawn(move || {
                while !reader_stop.load(Ordering::Acquire) {
                    let mut bytes = vec![0u8; 8192];
                    let read = match stdin.read(&mut bytes) {
                        Ok(0) => break,
                        Ok(count) => {
                            bytes.truncate(count);
                            Ok(bytes)
                        }
                        Err(error) => Err(error),
                    };
                    let failed = read.is_err();
                    if input_send.blocking_send(read).is_err() || failed {
                        break;
                    }
                }
            })?,
        stop: input_stop,
    };
    type Output = (Vec<u8>, oneshot::Sender<std::io::Result<()>>);
    let (output_send, mut output_receive) = mpsc::channel::<Output>(8);
    let output_stop = Arc::new(AtomicBool::new(false));
    let writer_stop = output_stop.clone();
    let output_thread = StdioThread {
        handle: std::thread::Builder::new()
            .name("mcp-bridge-stdout".into())
            .spawn(move || {
                while let Some((bytes, result)) = output_receive.blocking_recv() {
                    if writer_stop.load(Ordering::Acquire) {
                        break;
                    }
                    let write = stdout.write_all(&bytes).and_then(|()| stdout.flush());
                    let failed = write.is_err();
                    let _ = result.send(write);
                    if failed {
                        break;
                    }
                }
            })?,
        stop: output_stop,
    };
    let (mut read, mut write) = tokio::io::split(pipe);
    let input = async {
        while let Some(bytes) = input_receive.recv().await {
            write.write_all(&bytes?).await?;
        }
        write.shutdown().await?;
        anyhow::Ok(())
    };
    let output = async {
        let mut bytes = [0u8; 8192];
        loop {
            let count = read.read(&mut bytes).await?;
            if count == 0 {
                break;
            }
            let (result, receive) = oneshot::channel();
            output_send
                .send((bytes[..count].to_vec(), result))
                .await
                .context("stdio output thread stopped")?;
            receive
                .await
                .context("stdio output thread stopped without a result")??;
        }
        anyhow::Ok(())
    };
    let result = tokio::select! {
        result = input => result,
        result = output => result,
    };
    drop(input_thread);
    drop(output_thread);
    result
}

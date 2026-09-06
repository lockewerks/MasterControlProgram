use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

pub(crate) struct ObservedIo<T> {
    inner: T,
    disconnected: CancellationToken,
}

pub(crate) fn observe<R, W>(
    transport: (R, W),
    disconnected: CancellationToken,
) -> (ObservedIo<R>, ObservedIo<W>) {
    (
        ObservedIo {
            inner: transport.0,
            disconnected: disconnected.clone(),
        },
        ObservedIo {
            inner: transport.1,
            disconnected,
        },
    )
}

impl<T> Drop for ObservedIo<T> {
    fn drop(&mut self) {
        self.disconnected.cancel();
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for ObservedIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let requested = buffer.remaining();
        if requested == 0 {
            return Poll::Ready(Ok(()));
        }
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(context, buffer);
        if matches!(&result, Poll::Ready(Err(_)))
            || (requested != 0
                && matches!(&result, Poll::Ready(Ok(())))
                && buffer.filled().len() == before)
        {
            // The MCP service can still own pending responses after transport EOF.
            self.disconnected.cancel();
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ObservedIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(context, bytes);
        if matches!(&result, Poll::Ready(Err(_)))
            || (!bytes.is_empty() && matches!(&result, Poll::Ready(Ok(0))))
        {
            self.disconnected.cancel();
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_flush(context);
        if matches!(&result, Poll::Ready(Err(_))) {
            self.disconnected.cancel();
        }
        result
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_shutdown(context);
        if result.is_ready() {
            self.disconnected.cancel();
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn eof_cancels_even_with_a_live_writer_half() -> anyhow::Result<()> {
        let (transport, peer) = tokio::io::duplex(32);
        let disconnected = CancellationToken::new();
        let (mut reader, _writer) = observe(tokio::io::split(transport), disconnected.clone());
        drop(peer);
        assert_eq!(reader.read(&mut [0; 1]).await?, 0);
        assert!(disconnected.is_cancelled());
        Ok(())
    }

    #[tokio::test]
    async fn zero_length_read_is_not_a_disconnect() -> anyhow::Result<()> {
        let (transport, _peer) = tokio::io::duplex(32);
        let disconnected = CancellationToken::new();
        let (mut reader, _writer) = observe(tokio::io::split(transport), disconnected.clone());
        assert_eq!(reader.read(&mut []).await?, 0);
        assert!(!disconnected.is_cancelled());
        Ok(())
    }

    #[tokio::test]
    async fn failed_output_notifies_connection_cleanup() {
        let (transport, peer) = tokio::io::duplex(32);
        let disconnected = CancellationToken::new();
        let (_reader, mut writer) = observe(tokio::io::split(transport), disconnected.clone());
        drop(peer);
        assert!(writer.write_all(b"response").await.is_err());
        assert!(disconnected.is_cancelled());
    }
}

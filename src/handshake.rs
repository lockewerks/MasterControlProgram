//! The window before `initialize`, where a client can send a method this server
//! does not implement.
//!
//! rmcp waits for `initialize` and fails the handshake on anything else, which
//! ends the process. Copilot CLI opens every stdio connection with a
//! `server/discover` probe from the 2026-07-28 draft and falls back to
//! `initialize` when the server answers that it does not know the method. Exiting
//! is the one reply that leaves the fallback nothing to talk to: the client
//! writes its `initialize` into a broken pipe and reports the server as
//! unavailable. So answer the probe here and keep reading.

use std::io::{self, Cursor};

use serde_json::{json, Value};
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, Chain,
};

/// JSON-RPC's own "I do not implement this". The code carries the meaning, not
/// just the failure: Copilot reads -32601 as "legacy server, use initialize" and
/// treats -32602 as fatal (github/copilot-cli#4370).
const METHOD_NOT_FOUND: i32 = -32601;

/// What to do with one message that arrived before `initialize`.
enum Probe {
    /// Hand it to rmcp: either the request it is waiting for, or something we
    /// have no business answering on its behalf.
    Serve,
    /// Answered here. One JSON-RPC message, no trailing newline.
    Answer(Vec<u8>),
    /// Nothing to answer, and nothing rmcp could do with it but die.
    Ignore,
}

/// Read until `initialize` arrives, answering what the server can answer on its
/// own, and hand back a reader with the unconsumed bytes put back in front.
pub(crate) async fn answer_probes<R, W>(
    reader: R,
    writer: &mut W,
) -> io::Result<Chain<Cursor<Vec<u8>>, R>>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(reader);
    let mut pending = Vec::new();
    loop {
        let mut line = Vec::new();
        if reader.read_until(b'\n', &mut line).await? == 0 {
            // EOF before initialize. rmcp reports the closed connection.
            break;
        }
        match classify(&line) {
            Probe::Serve => {
                pending = line;
                break;
            }
            Probe::Answer(response) => {
                writer.write_all(&response).await?;
                writer.write_all(b"\n").await?;
                writer.flush().await?;
            }
            Probe::Ignore => {}
        }
    }
    // A buffered reader fills by the block, so the initialize line can arrive in
    // the same read as the notification and the first tool call behind it. Those
    // bytes are already out of the stream and would go with the wrapper.
    pending.extend_from_slice(reader.buffer());
    Ok(Cursor::new(pending).chain(reader.into_inner()))
}

fn classify(line: &[u8]) -> Probe {
    let Ok(message) = serde_json::from_slice::<Value>(line) else {
        // Malformed, or a batch. Neither is ours to answer, and rmcp failing on
        // it is the behaviour it has always had.
        return Probe::Serve;
    };
    let Some(method) = message.get("method").and_then(Value::as_str) else {
        return Probe::Serve;
    };
    let id = message.get("id").filter(|id| !id.is_null());
    match (method, id) {
        ("initialize", _) => Probe::Serve,
        // rmcp answers a pre-initialize ping itself, but only once it is reading
        // the stream, and it does not start until we hand the stream over. A
        // client that waits for the pong before initializing would wait forever.
        ("ping", Some(id)) => Probe::Answer(encode(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {},
        }))),
        (_, Some(id)) => {
            tracing::info!(
                method,
                "unimplemented request before initialize, answering not found"
            );
            Probe::Answer(encode(json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": METHOD_NOT_FOUND,
                    "message": format!("Method not found: {method}"),
                },
            })))
        }
        (_, None) => {
            tracing::debug!(method, "notification before initialize, dropped");
            Probe::Ignore
        }
    }
}

fn encode(message: Value) -> Vec<u8> {
    serde_json::to_vec(&message).expect("a JSON-RPC reply built from valid JSON serializes")
}

#[cfg(test)]
mod tests {
    use super::*;

    const DISCOVER: &str = r#"{"jsonrpc":"2.0","id":0,"method":"server/discover","params":{}}"#;
    const INITIALIZE: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;

    /// Returns what the server wrote back, and what rmcp would go on to read.
    async fn drain(input: &str) -> (Vec<Value>, String) {
        let mut written = Vec::new();
        let mut reader = answer_probes(Cursor::new(input.as_bytes().to_vec()), &mut written)
            .await
            .expect("drain the pre-initialize window");
        let mut served = String::new();
        reader
            .read_to_string(&mut served)
            .await
            .expect("read what was handed on");
        let replies = String::from_utf8(written)
            .expect("replies are UTF-8")
            .lines()
            .map(|line| serde_json::from_str(line).expect("replies are JSON"))
            .collect();
        (replies, served)
    }

    #[tokio::test]
    async fn unimplemented_probe_is_answered_and_initialize_still_arrives() {
        let (replies, served) = drain(&format!("{DISCOVER}\n{INITIALIZE}\n")).await;
        assert_eq!(replies.len(), 1, "one reply: {replies:?}");
        assert_eq!(replies[0]["id"], 0);
        assert_eq!(replies[0]["error"]["code"], METHOD_NOT_FOUND);
        assert_eq!(served, format!("{INITIALIZE}\n"));
    }

    #[tokio::test]
    async fn everything_behind_initialize_survives_the_handover() {
        let notification = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let list = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#;
        let (_, served) = drain(&format!(
            "{DISCOVER}\n{INITIALIZE}\n{notification}\n{list}\n"
        ))
        .await;
        assert_eq!(served, format!("{INITIALIZE}\n{notification}\n{list}\n"));
    }

    #[tokio::test]
    async fn a_ping_is_answered_here_rather_than_held_until_initialize() {
        let ping = r#"{"jsonrpc":"2.0","id":7,"method":"ping"}"#;
        let (replies, served) = drain(&format!("{ping}\n{INITIALIZE}\n")).await;
        assert_eq!(replies.len(), 1, "one reply: {replies:?}");
        assert_eq!(replies[0]["id"], 7);
        assert_eq!(replies[0]["result"], json!({}));
        assert_eq!(served, format!("{INITIALIZE}\n"));
    }

    #[tokio::test]
    async fn a_notification_before_initialize_is_dropped_rather_than_fatal() {
        let cancelled = r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{}}"#;
        let (replies, served) = drain(&format!("{cancelled}\n{INITIALIZE}\n")).await;
        assert!(replies.is_empty(), "nothing to answer: {replies:?}");
        assert_eq!(served, format!("{INITIALIZE}\n"));
    }

    #[tokio::test]
    async fn a_malformed_line_is_still_rmcps_to_reject() {
        let (replies, served) = drain("not json\n").await;
        assert!(replies.is_empty(), "nothing to answer: {replies:?}");
        assert_eq!(served, "not json\n");
    }

    #[tokio::test]
    async fn a_closed_stream_ends_the_wait() {
        let (replies, served) = drain(&format!("{DISCOVER}\n")).await;
        assert_eq!(replies.len(), 1, "one reply: {replies:?}");
        assert_eq!(served, "");
    }
}

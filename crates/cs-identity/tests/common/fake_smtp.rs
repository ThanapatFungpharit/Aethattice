//! A tiny in-test SMTP server (plaintext, loopback only): just enough of RFC 5321 for lettre.

#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cs_common::config::{SmtpConfig, SmtpTls};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

pub struct FakeSmtp {
    pub port: u16,
    pub mails: Arc<Mutex<Vec<String>>>,
    pub connections: Arc<AtomicU32>,
}

impl FakeSmtp {
    /// `delay`: wait before the greeting; `fail_first`: that many connections get
    /// `421` (transient) instead of a greeting.
    pub async fn start(delay: Duration, fail_first: u32) -> Self {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let mails = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicU32::new(0));
        let (m, c) = (mails.clone(), connections.clone());
        tokio::spawn(async move {
            while let Ok((sock, _)) = l.accept().await {
                let (m, n) = (m.clone(), c.fetch_add(1, Ordering::SeqCst) + 1);
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let (r, mut w) = sock.into_split();
                    if n <= fail_first {
                        let _ = w.write_all(b"421 4.3.2 try again later\r\n").await;
                        return;
                    }
                    let _ = w.write_all(b"220 fake ESMTP\r\n").await;
                    let mut lines = BufReader::new(r).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        let cmd = line.to_ascii_uppercase();
                        let reply: &[u8] = if cmd.starts_with("EHLO") || cmd.starts_with("HELO") {
                            b"250 fake\r\n"
                        } else if cmd.starts_with("DATA") {
                            let _ = w.write_all(b"354 go ahead\r\n").await;
                            let mut data = String::new();
                            while let Ok(Some(l)) = lines.next_line().await {
                                if l == "." {
                                    break;
                                }
                                data.push_str(&l);
                                data.push('\n');
                            }
                            m.lock().unwrap().push(decode_qp(&data));
                            b"250 queued\r\n"
                        } else if cmd.starts_with("QUIT") {
                            let _ = w.write_all(b"221 bye\r\n").await;
                            return;
                        } else {
                            b"250 ok\r\n"
                        };
                        let _ = w.write_all(reply).await;
                    }
                });
            }
        });
        Self {
            port,
            mails,
            connections,
        }
    }

    /// Relay configuration pointing at this server.
    pub fn config(&self) -> SmtpConfig {
        SmtpConfig {
            host: "127.0.0.1".into(),
            port: self.port,
            tls: SmtpTls::None,
            username: None,
            password: None,
            from: "Cloud System <no-reply@cs.example.com>".into(),
        }
    }

    /// Wait (up to `max`) for `n` messages.
    pub async fn wait_for(&self, n: usize, max: Duration) -> Vec<String> {
        let end = tokio::time::Instant::now() + max;
        loop {
            let v = self.mails.lock().unwrap().clone();
            if v.len() >= n || tokio::time::Instant::now() >= end {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

/// The `rt1` token of the recovery link in a delivered message.
pub fn link_token(mail: &str) -> Option<String> {
    let i = mail.find("/#/recover/")? + "/#/recover/".len();
    Some(
        mail[i..]
            .chars()
            .take_while(|c| !c.is_whitespace())
            .collect(),
    )
}

/// Undo quoted-printable (RFC 2045 §6.7) when the message declares it: soft line breaks and
/// `=XX` escapes. Other messages are returned unchanged.
fn decode_qp(data: &str) -> String {
    if !data.contains("Content-Transfer-Encoding: quoted-printable") {
        return data.to_owned();
    }
    let joined = data.replace("=\n", "");
    let b = joined.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'=' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&joined[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

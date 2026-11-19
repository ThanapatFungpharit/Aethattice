//! Black-box harness: runs the real `cs` binary with a generated config and talks HTTP to it.
//!
//! Binary: `$CS_QA_BIN`, else `<target dir>/debug/cs` (build it first: `cargo build -p cs`).
//! How the binary receives its config is bound in `contract::server_args` (OQ-20).

use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};

pub fn cs_binary() -> PathBuf {
    if let Ok(p) = std::env::var("CS_QA_BIN") {
        return PathBuf::from(p);
    }
    let target = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target"));
    let bin = target.join("debug").join("cs");
    assert!(
        bin.exists(),
        "cs binary not found at {} (run `cargo build -p cs` or set CS_QA_BIN)",
        bin.display()
    );
    bin
}

pub fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    l.local_addr().expect("local addr").port()
}

#[derive(Debug)]
pub struct Server {
    child: Child,
    pub base: String,
    pub dir: tempfile::TempDir,
}

pub fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("http client")
}

fn write_config(dir: &tempfile::TempDir, toml: &str) -> PathBuf {
    let path = dir.path().join("cs.toml");
    std::fs::write(&path, toml).expect("write config");
    path
}

fn spawn(config_path: &std::path::Path, dir: &tempfile::TempDir) -> Child {
    let mut cmd = Command::new(cs_binary());
    cmd.args(super::contract::server_args(config_path))
        .current_dir(dir.path())
        .env("RUST_BACKTRACE", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    cmd.spawn().expect("spawn cs binary")
}

async fn drain(child: &mut Child) -> String {
    let mut out = String::new();
    if let Some(mut s) = child.stdout.take() {
        let _ = s.read_to_string(&mut out).await;
    }
    if let Some(mut s) = child.stderr.take() {
        let _ = s.read_to_string(&mut out).await;
    }
    out
}

impl Server {
    /// Start the binary with `config` (built with the listen port `port`) and wait for /healthz.
    pub async fn start(config: &str, port: u16) -> Server {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_config(&dir, config);
        let mut child = spawn(&path, &dir);
        let base = format!("http://127.0.0.1:{port}");
        let client = http();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Ok(Some(status)) = child.try_wait() {
                let log = drain(&mut child).await;
                panic!(
                    "cs exited early with {status} during startup:\n{log}\n--- config ---\n{config}"
                );
            }
            if let Ok(r) = client.get(format!("{base}/healthz")).send().await
                && r.status().as_u16() == 200
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "cs did not answer /healthz with 200 within 30 s"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Server { child, base, dir }
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    pub async fn stop(mut self) -> String {
        let _ = self.child.start_kill();
        let _ = self.child.wait().await;
        drain(&mut self.child).await
    }
}

/// Run the binary with `config` and expect it to exit by itself (refusal paths).
/// Returns the exit status and the combined stdout+stderr. Panics if it keeps running.
pub async fn run_expect_exit(config: &str, timeout: Duration) -> (ExitStatus, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_config(&dir, config);
    let mut child = spawn(&path, &dir);
    let status = match tokio::time::timeout(timeout, child.wait()).await {
        Ok(s) => s.expect("wait cs"),
        Err(_) => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            let log = drain(&mut child).await;
            panic!(
                "cs kept running with a config it must refuse:\n{log}\n--- config ---\n{config}"
            );
        }
    };
    let log = drain(&mut child).await;
    (status, log)
}

/// True if something accepts TCP connections on the port.
pub async fn port_open(port: u16) -> bool {
    tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .is_ok()
}

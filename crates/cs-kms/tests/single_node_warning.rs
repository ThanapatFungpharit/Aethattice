//! The local software KMS logs a single-node warning (J.4) and never logs key material.
//! Own test binary: tracing caches callsite interest process-wide, so log capture must not
//! race other tests.

#![allow(clippy::unwrap_used)]

use cs_kms::{KeyPurpose, Kms, LocalSoftwareKms};
use std::io::Write;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn logs_single_node_warning_and_no_key_material() {
    let d = tempfile::tempdir().unwrap();
    let buf = Buf::default();
    let b2 = buf.clone();
    let sub = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || b2.clone())
        .finish();
    let root = d.path().join("root.key");
    let kms = tracing::subscriber::with_default(sub, || {
        let kms = LocalSoftwareKms::init(&root, None).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(kms.generate_key("k", KeyPurpose::Signing))
            .unwrap();
        kms
    });
    let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    assert!(out.contains("single-node"), "{out}");
    assert!(out.contains("WARN"));
    // no root key bytes in logs or Debug output
    let root_bytes = std::fs::read(&root).unwrap();
    let hex: String = root_bytes.iter().map(|b| format!("{b:02x}")).collect();
    assert!(!out.contains(&hex));
    let dbg = format!("{kms:?}");
    assert!(dbg.contains("REDACTED") && !dbg.contains(&hex));
}

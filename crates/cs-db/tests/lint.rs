//! Source lints for the database rules of contract §5 / §5.1 (spec §18.2, §8.3):
//!
//! 1. Transaction closures receive only the transaction handle (enforced by the
//!    `DomainPool::transaction` signature: `Fn(&mut DomainTx)`), and their bodies must not
//!    reference network clients (no network calls inside transactions).
//! 2. No DDL outside the migration runner (runtime DDL is forbidden).
//!
//! The scan covers non-test code of every crate (`crates/*/src`, up to the first
//! `#[cfg(test)]` of each file). It is a guard rail; review remains the primary control.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

const NETWORK_TOKENS: &[&str] = &[
    "reqwest",
    "hyper::",
    "TcpStream",
    "UdpSocket",
    "tonic::",
    "http::Request",
    "Kms",
    "kms.",
    "ToSocketAddrs",
];

const DDL_TOKENS: &[&str] = &[
    "CREATE TABLE",
    "ALTER TABLE",
    "DROP TABLE",
    "CREATE INDEX",
    "DROP INDEX",
    "CREATE DATABASE",
    "DROP DATABASE",
    "TRUNCATE ",
    "CREATE SCHEMA",
    "CREATE TRIGGER",
    "CREATE FUNCTION",
];

/// Files allowed to contain DDL.
const DDL_ALLOWED: &[&str] = &["cs-db/src/migrate.rs", "cs-db/src/testing.rs"];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

fn non_test_part(text: &str) -> &str {
    text.find("#[cfg(test)]").map_or(text, |i| &text[..i])
}

/// Return the text of the argument list of each `.transaction(` / `.read_snapshot(` call.
fn transaction_args(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for needle in [".transaction(", ".read_snapshot("] {
        let mut from = 0;
        while let Some(i) = text[from..].find(needle) {
            let start = from + i + needle.len();
            let mut depth = 1;
            let mut end = start;
            for (j, c) in text[start..].char_indices() {
                match c {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            end = start + j;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            out.push(text[start..end].to_owned());
            from = start;
        }
    }
    out
}

fn network_violations(text: &str) -> Vec<String> {
    transaction_args(non_test_part(text))
        .into_iter()
        .filter_map(|arg| {
            NETWORK_TOKENS
                .iter()
                .find(|t| arg.contains(*t))
                .map(|t| format!("transaction closure references `{t}`"))
        })
        .collect()
}

fn ddl_violations(text: &str) -> Vec<String> {
    let upper = non_test_part(text).to_uppercase();
    DDL_TOKENS
        .iter()
        .filter(|t| upper.contains(*t))
        .map(|t| format!("DDL `{}` outside the migration runner", t.trim()))
        .collect()
}

#[test]
fn lint_detects_violations() {
    let bad_tx = "pool.transaction(move |tx| Box::pin(async move { client.get(reqwest::Url::parse(\"x\")); Ok(()) }))";
    assert_eq!(network_violations(bad_tx).len(), 1);
    let bad_kms = "p.transaction(|tx| Box::pin(async move { kms.sign(&k, b\"\").await; Ok(()) }))";
    assert_eq!(network_violations(bad_kms).len(), 1);
    let ok_tx = "pool.transaction(|tx| Box::pin(async move { sqlx::query(\"SELECT 1\").execute(tx.conn()).await?; Ok(()) }))";
    assert!(network_violations(ok_tx).is_empty());
    assert_eq!(
        ddl_violations("sqlx::query(\"create table x (a int)\")").len(),
        1
    );
    assert!(
        ddl_violations("fn f() {}\n#[cfg(test)]\nmod t { const X: &str = \"CREATE TABLE x\"; }")
            .is_empty()
    );
}

#[test]
fn no_network_in_transactions_and_no_runtime_ddl() {
    let root = workspace_root().join("crates");
    let mut files = Vec::new();
    for krate in std::fs::read_dir(&root).unwrap().flatten() {
        rust_files(&krate.path().join("src"), &mut files);
    }
    assert!(!files.is_empty());
    let mut problems = Vec::new();
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap();
        let rel = f
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        for v in network_violations(&text) {
            problems.push(format!("{rel}: {v}"));
        }
        if !DDL_ALLOWED.iter().any(|a| rel == *a) {
            for v in ddl_violations(&text) {
                problems.push(format!("{rel}: {v}"));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "lint violations:\n{}",
        problems.join("\n")
    );
}

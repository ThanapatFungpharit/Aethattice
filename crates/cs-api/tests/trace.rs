//! W3C Trace Context propagation (contract §8, spec §25.1; QA gate F-3).
//!
//! An incoming `traceparent` is continued by the request's span (same trace ID, the caller's
//! span as remote parent), and the request's log lines carry that trace ID. Observed through
//! an in-memory OpenTelemetry span exporter and captured JSON logs. Own test binary: it
//! installs a tracing subscriber and the global propagator.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use opentelemetry::trace::{SpanId, TraceId, TracerProvider as _};
use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider, SpanData};
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tower::ServiceExt;
use tracing_subscriber::layer::SubscriberExt;

const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
const PARENT_SPAN_ID: &str = "00f067aa0ba902b7";

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

fn request_spans(spans: &[SpanData]) -> Vec<&SpanData> {
    spans.iter().filter(|s| s.name == "http_request").collect()
}

#[tokio::test]
async fn incoming_traceparent_is_continued_in_span_and_logs() {
    let exporter = InMemorySpanExporterBuilder::new().build();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let logs = Buf::default();
    let w = logs.clone();
    let subscriber = tracing_subscriber::registry()
        .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("cs-test")))
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_current_span(true)
                .with_ansi(false)
                .with_writer(move || w.clone()),
        );
    let _guard = tracing::subscriber::set_default(subscriber);
    cs_common::telemetry::install_propagator();

    let state = cs_api::ApiState::new("trace.example", vec![], Duration::from_secs(1));
    let app = cs_api::router(state, 1024);

    // 1. With a valid traceparent: same trace, remote parent = caller's span.
    let req = Request::get("/healthz")
        .header("traceparent", format!("00-{TRACE_ID}-{PARENT_SPAN_ID}-01"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK
    );
    provider.force_flush().unwrap();
    let spans = exporter.get_finished_spans().unwrap();
    let ours = request_spans(&spans);
    assert_eq!(ours.len(), 1, "{spans:?}");
    let s = ours[0];
    assert_eq!(
        s.span_context.trace_id(),
        TraceId::from_hex(TRACE_ID).unwrap()
    );
    assert_eq!(s.parent_span_id, SpanId::from_hex(PARENT_SPAN_ID).unwrap());
    assert!(s.parent_span_is_remote);
    assert_ne!(
        s.span_context.span_id(),
        SpanId::from_hex(PARENT_SPAN_ID).unwrap()
    );
    let own_span_id = s.span_context.span_id().to_string();
    let text = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    let line = text
        .lines()
        .find(|l| l.contains("request completed"))
        .unwrap_or_else(|| panic!("no request log line in {text}"));
    let v: serde_json::Value = serde_json::from_str(line).unwrap();
    assert_eq!(v["span"]["trace_id"], TRACE_ID, "{line}");
    assert_eq!(v["span"]["span_id"], own_span_id.as_str(), "{line}");
    assert!(v["span"]["request_id"].is_string());

    // 2. Without (or with a malformed) traceparent: a fresh trace is started, never reused.
    exporter.reset();
    logs.0.lock().unwrap().clear();
    for header in [None, Some("00-zzzz-not-a-traceparent")] {
        let mut r = Request::get("/healthz");
        if let Some(h) = header {
            r = r.header("traceparent", h);
        }
        assert_eq!(
            app.clone()
                .oneshot(r.body(Body::empty()).unwrap())
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }
    provider.force_flush().unwrap();
    let spans = exporter.get_finished_spans().unwrap();
    let ours = request_spans(&spans);
    assert_eq!(ours.len(), 2);
    for s in &ours {
        assert!(s.span_context.is_valid());
        assert_ne!(
            s.span_context.trace_id(),
            TraceId::from_hex(TRACE_ID).unwrap()
        );
        assert_eq!(
            s.parent_span_id,
            SpanId::INVALID,
            "no parent without a valid traceparent"
        );
    }
    assert_ne!(
        ours[0].span_context.trace_id(),
        ours[1].span_context.trace_id()
    );
    let text = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    let traced: Vec<_> = text
        .lines()
        .filter(|l| l.contains("request completed"))
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()["span"]["trace_id"].clone())
        .collect();
    assert_eq!(traced.len(), 2);
    let span_traces: Vec<String> = ours
        .iter()
        .map(|s| s.span_context.trace_id().to_string())
        .collect();
    for t in &traced {
        let t = t.as_str().unwrap_or_default();
        assert!(t.len() == 32 && t != TRACE_ID, "{t}");
        assert!(
            span_traces.iter().any(|s| s == t),
            "log trace_id {t} matches an exported span"
        );
    }
}

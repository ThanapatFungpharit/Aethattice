//! Telemetry setup (contract §8, spec §25.1).
//!
//! - Structured JSON logs (or text for local development) via `tracing`.
//! - OpenTelemetry tracing with W3C Trace Context propagation (`traceparent`/`tracestate`);
//!   the global propagator is set here and used by the HTTP layer to extract the parent.
//! - Prometheus-compatible metrics through the `metrics` facade; the HTTP admin listener
//!   renders them at `/metrics`.
//!
//! Secrets are never logged: configuration secrets are `Secret<T>` (no Debug/Display output)
//! and error causes are logged only server-side.
//!
//! In M0 no span exporter is configured (spans carry trace context for propagation and log
//! correlation only). An OTLP exporter is added when an operator-facing collector exists.

use crate::config::{LogFormat, TelemetryConfig};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::SdkTracerProvider;
use thiserror::Error;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Debug, Error)]
pub enum TelemetryError {
    #[error("invalid log filter: {0}")]
    Filter(String),
    #[error("telemetry already initialised: {0}")]
    AlreadyInitialised(String),
}

/// Keeps telemetry providers alive; dropping it flushes the tracer provider.
#[derive(Debug)]
pub struct Telemetry {
    provider: SdkTracerProvider,
    metrics: PrometheusHandle,
}

impl Telemetry {
    /// Prometheus text exposition of all registered metrics.
    pub fn render_metrics(&self) -> String {
        self.metrics.render()
    }

    pub fn metrics_handle(&self) -> PrometheusHandle {
        self.metrics.clone()
    }
}

impl Drop for Telemetry {
    fn drop(&mut self) {
        let _ = self.provider.shutdown();
    }
}

/// Install the global tracing subscriber, propagator and metrics recorder. Call once per
/// process.
pub fn init(cfg: &TelemetryConfig) -> Result<Telemetry, TelemetryError> {
    let filter =
        EnvFilter::try_new(&cfg.log_level).map_err(|e| TelemetryError::Filter(e.to_string()))?;
    install_propagator();
    let provider = SdkTracerProvider::builder()
        .with_resource(
            Resource::builder()
                .with_service_name(cfg.service_name.clone())
                .build(),
        )
        .build();
    let tracer = provider.tracer("cs");
    let otel = tracing_opentelemetry::layer().with_tracer(tracer);
    let registry = tracing_subscriber::registry().with(filter).with(otel);
    let res = match cfg.log_format {
        LogFormat::Json => registry
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_current_span(true)
                    .with_span_list(false),
            )
            .try_init(),
        LogFormat::Text => registry.with(tracing_subscriber::fmt::layer()).try_init(),
    };
    res.map_err(|e| TelemetryError::AlreadyInitialised(e.to_string()))?;
    let metrics = PrometheusBuilder::new()
        .install_recorder()
        .map_err(|e| TelemetryError::AlreadyInitialised(e.to_string()))?;
    Ok(Telemetry { provider, metrics })
}

/// Install the W3C Trace Context propagator (`traceparent` / `tracestate`) globally.
pub fn install_propagator() {
    opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());
}

/// A metrics handle without installing global logging (tests and embedded use).
pub fn standalone_metrics() -> PrometheusHandle {
    PrometheusBuilder::new().build_recorder().handle()
}

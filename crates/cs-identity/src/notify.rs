//! Out-of-band notifications of the identity domain (contract §4).
//!
//! The email recovery link (rev 10) is a bearer secret, so it never goes through the outbox
//! or the API: after the request commits, the service hands it to a [`Notifier`]. Everything
//! without a secret (a recovery was requested, approved, completed) is an outbox event, which
//! the notification service (M4) delivers to all of the user's devices.
//!
//! M1 ships the trait, [`Discard`] (no delivery configured: the link is dropped and a warning
//! without the secret is logged) and [`DevLogSink`]. `[R7]` The log sink writes bearer
//! secrets, so it can only be built for the explicit `--dev` profile and prefixes every line
//! with `DEV-ONLY SECRET`. The SMTP relay implementation is not part of this slice.

use async_trait::async_trait;
use cs_common::error::{Error, ErrorCode};
use cs_common::secret::Secret;

/// Delivery of recovery links.
#[async_trait]
pub trait Notifier: Send + Sync {
    /// Send the email recovery link token (an `rt1` token) to the verified address.
    async fn recovery_link(&self, to: &str, token: &Secret<String>) -> Result<(), Error>;
}

/// No delivery configured.
#[derive(Debug, Clone, Copy, Default)]
pub struct Discard;

#[async_trait]
impl Notifier for Discard {
    async fn recovery_link(&self, _to: &str, _token: &Secret<String>) -> Result<(), Error> {
        tracing::warn!("no notifier configured: an email recovery link was not delivered");
        Ok(())
    }
}

/// `[R7]` Development sink: logs the link. Refused outside the `--dev` profile.
#[derive(Debug, Clone, Copy)]
pub struct DevLogSink(());

impl DevLogSink {
    /// `dev_profile`: whether `cs serve` runs with `--dev`.
    pub fn new(dev_profile: bool) -> Result<Self, Box<Error>> {
        if dev_profile {
            Ok(Self(()))
        } else {
            Err(Box::new(Error::new(ErrorCode::InvalidRequest).with_detail(
                "the log notifier writes bearer secrets and needs the --dev profile",
            )))
        }
    }
}

#[async_trait]
impl Notifier for DevLogSink {
    async fn recovery_link(&self, to: &str, token: &Secret<String>) -> Result<(), Error> {
        tracing::warn!(
            "DEV-ONLY SECRET recovery link for {to}: #/recover/{}",
            token.expose_secret()
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_sink_needs_dev_profile() {
        assert!(DevLogSink::new(false).is_err());
        assert!(DevLogSink::new(true).is_ok());
    }
}

//! OPAQUE client for the browser (M1 contract rev 5 §2.1): `opaque-ke` with the suite, context and client
//! identifier from `cs-identity-wire`, the same crate the server uses, compiled to WASM.
//!
//! Argon2id (the KSF) runs here, on the client, with the parameters the server sent in `ksf_params`.
//! The export key and the session key are dropped: M1 needs neither (the vault, M9, will use the export key).
//! Protocol state stays inside WASM memory; JS only holds an opaque handle.

use cs_identity_wire::{CONTEXT, KsfParams, Suite as CsOpaqueSuite, client_identifier, login};
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, Identifiers, RegistrationResponse,
};
use rand::rngs::OsRng;
use wasm_bindgen::prelude::*;

/// Error message for a failed login finish (wrong password, unknown account, or a tampered response).
/// RFC 9807 makes these indistinguishable to the client as well.
pub const ERR_INVALID_LOGIN: &str = "invalid_login";

/// Core errors, as plain strings so the logic is testable off-wasm. Never contains secret material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientError(pub String);

impl ClientError {
    fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

/// True for the canonical UUID text form (M0 contract: lowercase, hyphenated). Rev 5 §2.1: `tenant` is always
/// the tenant UUID in that form.
pub fn is_canonical_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, &c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(&c),
        })
}

/// `<tenant UUID>/<normalized login>` (rev 5 §2.1), after validating both parts.
fn identifier(tenant: &str, raw_login: &str) -> Result<String, ClientError> {
    if !is_canonical_uuid(tenant) {
        return Err(ClientError::new("tenant must be a canonical UUID"));
    }
    let normalized =
        login::normalize_login(raw_login).map_err(|e| ClientError::new(e.to_string()))?;
    Ok(client_identifier(tenant, &normalized))
}

fn ksf(params: KsfParams) -> Result<argon2::Argon2<'static>, ClientError> {
    params.argon2().map_err(|e| ClientError::new(e.to_string()))
}

/// The client refuses KSF parameters outside the rev 7 bounds (`65536 ≤ m_kib ≤ 262144`, `3 ≤ t ≤ 10`,
/// `1 ≤ p ≤ 4`) before Argon2id runs, so a hostile or broken server cannot make it exhaust memory or time.
pub fn check_ksf_bounds(params: KsfParams) -> Result<KsfParams, ClientError> {
    if params.is_valid() {
        Ok(params)
    } else {
        Err(ClientError::new("ksf_params outside the contract bounds"))
    }
}

/// Registration refuses KSF parameters below the contract default (rev 5: the server rejects them too), so a
/// misbehaving server cannot make the client store a cheaper-to-attack record, and anything above the rev 7
/// upper bounds.
pub fn check_registration_ksf(params: KsfParams) -> Result<KsfParams, ClientError> {
    if !params.meets_minimum() {
        return Err(ClientError::new("ksf_params below the minimum"));
    }
    check_ksf_bounds(params)
}

/// Registration in progress: holds the client state between `register/start` and `register/finish`.
#[wasm_bindgen]
#[derive(Debug)]
pub struct RegistrationClient {
    state: ClientRegistration<CsOpaqueSuite>,
    request: Vec<u8>,
    id: String,
}

impl RegistrationClient {
    /// Validates the identity, blinds the password and produces the `registration_request`.
    pub fn begin(password: &[u8], tenant: &str, login: &str) -> Result<Self, ClientError> {
        let id = identifier(tenant, login)?;
        let r = ClientRegistration::<CsOpaqueSuite>::start(&mut OsRng, password)
            .map_err(|e| ClientError::new(e.to_string()))?;
        Ok(Self {
            request: r.message.serialize().to_vec(),
            state: r.state,
            id,
        })
    }

    /// Unblinds the `registration_response`, runs Argon2id and produces the `registration_upload`.
    pub fn complete(
        self,
        password: &[u8],
        response: &[u8],
        ksf_params: KsfParams,
    ) -> Result<Vec<u8>, ClientError> {
        let id = self.id;
        let ksf = ksf(ksf_params)?;
        let response = RegistrationResponse::<CsOpaqueSuite>::deserialize(response)
            .map_err(|e| ClientError::new(e.to_string()))?;
        let params = ClientRegistrationFinishParameters::new(
            Identifiers {
                client: Some(id.as_bytes()),
                server: None,
            },
            Some(&ksf),
        );
        let r = self
            .state
            .finish(&mut OsRng, password, response, params)
            .map_err(|e| ClientError::new(e.to_string()))?;
        Ok(r.message.serialize().to_vec())
    }
}

#[wasm_bindgen]
impl RegistrationClient {
    /// `registration_request` bytes.
    #[wasm_bindgen(getter)]
    pub fn request(&self) -> Vec<u8> {
        self.request.clone()
    }

    /// Consumes the handle. Returns the `registration_upload` bytes.
    pub fn finish(
        self,
        password: &[u8],
        response: &[u8],
        m_kib: u32,
        t: u32,
        p: u32,
    ) -> Result<Vec<u8>, JsError> {
        check_registration_ksf(KsfParams { m_kib, t, p })
            .and_then(|k| self.complete(password, response, k))
            .map_err(|e| JsError::new(&e.0))
    }
}

/// Starts a registration (contract §2.1 `register/start`). `tenant` is the canonical tenant UUID, `login` as
/// typed (it is normalized here, rev 5 §2.1).
#[wasm_bindgen(js_name = registrationStart)]
pub fn registration_start(
    password: &[u8],
    tenant: &str,
    login: &str,
) -> Result<RegistrationClient, JsError> {
    RegistrationClient::begin(password, tenant, login).map_err(|e| JsError::new(&e.0))
}

/// Login in progress: holds the client state between `login/start` and `login/finish`.
#[wasm_bindgen]
#[derive(Debug)]
pub struct LoginClient {
    state: ClientLogin<CsOpaqueSuite>,
    request: Vec<u8>,
    id: String,
}

impl LoginClient {
    /// Validates the identity, blinds the password and produces the `credential_request` (KE1).
    pub fn begin(password: &[u8], tenant: &str, login: &str) -> Result<Self, ClientError> {
        let id = identifier(tenant, login)?;
        let r = ClientLogin::<CsOpaqueSuite>::start(&mut OsRng, password)
            .map_err(|e| ClientError::new(e.to_string()))?;
        Ok(Self {
            request: r.message.serialize().to_vec(),
            state: r.state,
            id,
        })
    }

    /// Processes the `credential_response` (KE2), runs Argon2id, and produces the `credential_finalization`
    /// (KE3). Fails with [`ERR_INVALID_LOGIN`] when the server could not be authenticated.
    pub fn complete(
        self,
        password: &[u8],
        response: &[u8],
        ksf_params: KsfParams,
    ) -> Result<Vec<u8>, ClientError> {
        let id = self.id;
        let ksf = ksf(ksf_params)?;
        let response = CredentialResponse::<CsOpaqueSuite>::deserialize(response)
            .map_err(|e| ClientError::new(e.to_string()))?;
        let params = ClientLoginFinishParameters::new(
            Some(CONTEXT),
            Identifiers {
                client: Some(id.as_bytes()),
                server: None,
            },
            Some(&ksf),
        );
        let r = self
            .state
            .finish(&mut OsRng, password, response, params)
            .map_err(|e| match e {
                opaque_ke::errors::ProtocolError::InvalidLoginError => {
                    ClientError::new(ERR_INVALID_LOGIN)
                }
                other => ClientError::new(other.to_string()),
            })?;
        Ok(r.message.serialize().to_vec())
    }
}

#[wasm_bindgen]
impl LoginClient {
    /// `credential_request` bytes.
    #[wasm_bindgen(getter)]
    pub fn request(&self) -> Vec<u8> {
        self.request.clone()
    }

    /// Consumes the handle. Returns the `credential_finalization` bytes.
    pub fn finish(
        self,
        password: &[u8],
        response: &[u8],
        m_kib: u32,
        t: u32,
        p: u32,
    ) -> Result<Vec<u8>, JsError> {
        check_ksf_bounds(KsfParams { m_kib, t, p })
            .and_then(|k| self.complete(password, response, k))
            .map_err(|e| JsError::new(&e.0))
    }
}

/// Starts a login (contract §2.1 `login/start`). `tenant` is the canonical tenant UUID, `login` as typed.
#[wasm_bindgen(js_name = loginStart)]
pub fn login_start(password: &[u8], tenant: &str, login: &str) -> Result<LoginClient, JsError> {
    LoginClient::begin(password, tenant, login).map_err(|e| JsError::new(&e.0))
}

/// The shared login normalization (contract §1, rev 5 §2.1), so the UI can validate before the round trip.
#[wasm_bindgen(js_name = normalizeLogin)]
pub fn normalize_login(raw: &str) -> Result<String, JsError> {
    login::normalize_login(raw).map_err(|e| JsError::new(&e.to_string()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use opaque_ke::{
        CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
        ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
    };

    const TENANT: &str = "01934f6e-7c1a-7d2b-8e3f-4a5b6c7d8e9f";
    // Small but RFC 9106-valid parameters keep the test fast; the production default is DEFAULT_KSF.
    const FAST: KsfParams = KsfParams {
        m_kib: 64,
        t: 1,
        p: 1,
    };

    /// Plays the server with the same suite, context and identifiers the server crate uses.
    fn register(
        setup: &ServerSetup<CsOpaqueSuite>,
        password: &[u8],
        login: &str,
    ) -> ServerRegistration<CsOpaqueSuite> {
        let id = identifier(TENANT, login).unwrap();
        let c = RegistrationClient::begin(password, TENANT, login).unwrap();
        let req = RegistrationRequest::deserialize(&c.request).unwrap();
        let resp = ServerRegistration::start(setup, req, id.as_bytes()).unwrap();
        let upload = c
            .complete(password, &resp.message.serialize(), FAST)
            .unwrap();
        ServerRegistration::finish(RegistrationUpload::deserialize(&upload).unwrap())
    }

    fn login(
        setup: &ServerSetup<CsOpaqueSuite>,
        record: Option<ServerRegistration<CsOpaqueSuite>>,
        password: &[u8],
        login: &str,
    ) -> Result<bool, ClientError> {
        let id = identifier(TENANT, login).unwrap();
        let c = LoginClient::begin(password, TENANT, login)?;
        let req = CredentialRequest::deserialize(&c.request).unwrap();
        let start = ServerLogin::start(
            &mut OsRng,
            setup,
            record,
            req,
            id.as_bytes(),
            ServerLoginParameters {
                context: Some(CONTEXT),
                identifiers: Identifiers {
                    client: Some(id.as_bytes()),
                    server: None,
                },
            },
        )
        .unwrap();
        let fin = c.complete(password, &start.message.serialize(), FAST)?;
        let fin = CredentialFinalization::deserialize(&fin).unwrap();
        Ok(start
            .state
            .finish(
                fin,
                ServerLoginParameters {
                    context: Some(CONTEXT),
                    identifiers: Identifiers {
                        client: Some(id.as_bytes()),
                        server: None,
                    },
                },
            )
            .is_ok())
    }

    #[test]
    fn register_then_login_round_trip_against_opaque_ke_server() {
        let setup = ServerSetup::<CsOpaqueSuite>::new(&mut OsRng);
        let record = register(&setup, b"correct horse", "Alice@Example.com");
        // The login is normalized into the identifier, so a different case still signs in.
        assert_eq!(
            login(&setup, Some(record), b"correct horse", "alice@example.com"),
            Ok(true)
        );
    }

    #[test]
    fn wrong_password_and_unknown_account_both_fail_as_invalid_login() {
        let setup = ServerSetup::<CsOpaqueSuite>::new(&mut OsRng);
        let record = register(&setup, b"correct horse", "alice");
        assert_eq!(
            login(&setup, Some(record), b"wrong", "alice"),
            Err(ClientError::new(ERR_INVALID_LOGIN))
        );
        // Dummy-record path for an unknown account (§2.1 [R3]).
        assert_eq!(
            login(&setup, None, b"anything", "bob"),
            Err(ClientError::new(ERR_INVALID_LOGIN))
        );
    }

    #[test]
    fn different_ksf_params_at_login_fail() {
        let setup = ServerSetup::<CsOpaqueSuite>::new(&mut OsRng);
        let record = register(&setup, b"pw", "alice");
        let id = identifier(TENANT, "alice").unwrap();
        let c = LoginClient::begin(b"pw", TENANT, "alice").unwrap();
        let req = CredentialRequest::deserialize(&c.request).unwrap();
        let p = ServerLoginParameters {
            context: Some(CONTEXT),
            identifiers: Identifiers {
                client: Some(id.as_bytes()),
                server: None,
            },
        };
        let start =
            ServerLogin::start(&mut OsRng, &setup, Some(record), req, id.as_bytes(), p).unwrap();
        let other = KsfParams {
            m_kib: 64,
            t: 2,
            p: 1,
        };
        assert_eq!(
            c.complete(b"pw", &start.message.serialize(), other),
            Err(ClientError::new(ERR_INVALID_LOGIN))
        );
    }

    #[test]
    fn invalid_inputs_rejected_before_crypto() {
        let c = LoginClient::begin(b"pw", TENANT, "alice").unwrap();
        assert!(c.complete(b"pw", &[0u8; 3], FAST).is_err());
        let c = LoginClient::begin(b"pw", TENANT, "alice").unwrap();
        let bad = KsfParams {
            m_kib: 1,
            t: 1,
            p: 1,
        };
        assert!(c.complete(b"pw", &[], bad).is_err());
        assert!(LoginClient::begin(b"pw", "ACME", "alice").is_err());
        assert!(RegistrationClient::begin(b"pw", TENANT, " alice").is_err());
    }

    #[test]
    fn registration_refuses_ksf_below_contract_default() {
        assert_eq!(
            check_registration_ksf(KsfParams::DEFAULT),
            Ok(KsfParams::DEFAULT)
        );
        assert!(check_registration_ksf(FAST).is_err());
        assert!(
            check_registration_ksf(KsfParams {
                m_kib: 65_536,
                t: 2,
                p: 1
            })
            .is_err()
        );
    }

    #[test]
    fn ksf_outside_rev7_bounds_refused_before_argon2() {
        assert_eq!(check_ksf_bounds(KsfParams::DEFAULT), Ok(KsfParams::DEFAULT));
        let max = KsfParams {
            m_kib: 262_144,
            t: 10,
            p: 4,
        };
        assert_eq!(check_ksf_bounds(max), Ok(max));
        for bad in [
            KsfParams {
                m_kib: 65_535,
                t: 3,
                p: 1,
            },
            KsfParams {
                m_kib: 262_145,
                t: 3,
                p: 1,
            },
            KsfParams {
                m_kib: 65_536,
                t: 2,
                p: 1,
            },
            KsfParams {
                m_kib: 65_536,
                t: 11,
                p: 1,
            },
            KsfParams {
                m_kib: 65_536,
                t: 3,
                p: 0,
            },
            KsfParams {
                m_kib: 65_536,
                t: 3,
                p: 5,
            },
            KsfParams {
                m_kib: u32::MAX,
                t: u32::MAX,
                p: u32::MAX,
            },
        ] {
            assert!(check_ksf_bounds(bad).is_err(), "{bad:?}");
            assert!(check_registration_ksf(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn tenant_must_be_canonical_uuid() {
        assert!(is_canonical_uuid(TENANT));
        assert!(!is_canonical_uuid(&TENANT.to_uppercase()));
        assert!(!is_canonical_uuid("acme"));
        assert_eq!(
            identifier(TENANT, "Alice").unwrap(),
            format!("{TENANT}/alice")
        );
    }
}

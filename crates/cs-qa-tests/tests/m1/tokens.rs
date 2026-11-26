//! Access-token verification (contract §3, [R12]; M0-gate §6.1 "JWS").
use crate::fx::*;
use serde_json::{Value, json};

/// A valid token, the header and claims it carries, for tampering.
async fn base(e: &Env) -> (Session, Value, Value) {
    let t = e.tenant().await;
    let u = e.user(t, "alice", "pw-tokens-1").await;
    let s = e.login(&u).await;
    let parts: Vec<&str> = s.at.split('.').collect();
    let h: Value = serde_json::from_slice(&unb64(parts[0])).unwrap();
    let c: Value = serde_json::from_slice(&unb64(parts[1])).unwrap();
    (s, h, c)
}

async fn me(e: &Env, at: &str) -> Resp {
    e.call(Req::get("/api/v2/me").bearer(at)).await
}

#[tokio::test]
async fn access_token_shape_and_jwks() {
    let Some(e) = Env::default().await else {
        return;
    };
    let (s, h, c) = base(&e).await;
    me(&e, &s.at).await.expect(200);
    assert_eq!(h["alg"], "EdDSA");
    assert_eq!(h["typ"], "at+jwt");
    assert_eq!(h.as_object().unwrap().len(), 3, "header: {h}");
    assert_eq!(c["iss"], format!("https://{DOMAIN}"));
    assert_eq!(c["aud"], format!("https://{DOMAIN}/api/v2"));
    for k in [
        "sub",
        "tid",
        "sid",
        "sgen",
        "amr",
        "auth_time",
        "iat",
        "exp",
        "jti",
    ] {
        assert!(c.get(k).is_some(), "claim {k} missing: {c}");
    }
    assert!(c.get("av").is_none(), "[R9]: av is reserved for M2");
    assert_eq!(c["exp"].as_i64().unwrap() - c["iat"].as_i64().unwrap(), 600);
    let j = e.call(Req::get("/api/v2/auth/jwks")).await;
    j.expect(200);
    let keys = j.body["keys"].as_array().unwrap();
    assert!(keys.iter().any(|k| k["kid"] == h["kid"]), "{}", j.body);
    for k in keys {
        for private in ["d", "p", "q", "dp", "dq", "qi", "k"] {
            assert!(
                k.get(private).is_none(),
                "JWKS leaks private member {private}"
            );
        }
    }
    e.finish().await;
}

/// `alg: none`, HS256 keyed with the public key, unknown `kid`, `jku`/`jwk`/`x5u`/`x5c`/`crit`
/// headers (validly signed), `typ` other than `at+jwt`, tampered payload and signature.
#[tokio::test]
async fn jws_alg_confusion_kid_and_header_injection_rejected() {
    let Some(e) = Env::default().await else {
        return;
    };
    let (s, h, c) = base(&e).await;
    let parts: Vec<&str> = s.at.split('.').collect();
    let mut bad: Vec<(String, String)> = Vec::new();
    // alg none (with and without signature segment).
    let hn = json!({"alg": "none", "typ": "at+jwt", "kid": h["kid"]});
    let none = format!("{}.{}.", b64(hn.to_string().as_bytes()), parts[1]);
    bad.push(("alg none".into(), none.clone()));
    bad.push(("alg none, no dot".into(), none.trim_end_matches('.').into()));
    // HS256 keyed with the public key from the JWKS.
    let jwks = e.call(Req::get("/api/v2/auth/jwks")).await;
    let x = jwks.body["keys"][0]["x"].as_str().unwrap().to_owned();
    for key in [unb64(&x), x.as_bytes().to_vec()] {
        let hh = json!({"alg": "HS256", "typ": "at+jwt", "kid": h["kid"]});
        let input = format!("{}.{}", b64(hh.to_string().as_bytes()), parts[1]);
        let mac = hmac_sha256(&key, input.as_bytes());
        bad.push((
            "HS256 with public key".into(),
            format!("{input}.{}", b64(&mac)),
        ));
    }
    // Validly signed by the real key but with forbidden or unknown header members.
    let kid = current_kid(&e).await;
    let name = kid.split('@').next().unwrap().to_owned();
    let variants = vec![
        (
            "unknown kid version",
            json!({"alg": "EdDSA", "typ": "at+jwt", "kid": format!("{name}@v99")}),
        ),
        (
            "unknown kid name",
            json!({"alg": "EdDSA", "typ": "at+jwt", "kid": "qa-other@v1"}),
        ),
        ("kid missing", json!({"alg": "EdDSA", "typ": "at+jwt"})),
        (
            "jku header",
            json!({"alg": "EdDSA", "typ": "at+jwt", "kid": kid, "jku": "https://evil.example/jwks"}),
        ),
        (
            "jwk header",
            json!({"alg": "EdDSA", "typ": "at+jwt", "kid": kid, "jwk": {"kty": "OKP", "crv": "Ed25519", "x": x}}),
        ),
        (
            "x5u header",
            json!({"alg": "EdDSA", "typ": "at+jwt", "kid": kid, "x5u": "https://evil.example/c.pem"}),
        ),
        (
            "x5c header",
            json!({"alg": "EdDSA", "typ": "at+jwt", "kid": kid, "x5c": ["MIIB"]}),
        ),
        (
            "crit header",
            json!({"alg": "EdDSA", "typ": "at+jwt", "kid": kid, "crit": ["exp"]}),
        ),
        ("typ JWT", json!({"alg": "EdDSA", "typ": "JWT", "kid": kid})),
        (
            "typ dpop+jwt",
            json!({"alg": "EdDSA", "typ": "dpop+jwt", "kid": kid}),
        ),
        (
            "alg Ed25519 spelling",
            json!({"alg": "Ed25519", "typ": "at+jwt", "kid": kid}),
        ),
    ];
    for (n, hv) in variants {
        bad.push((n.into(), sign_with_kms(&e, &hv, &c).await));
    }
    // Tampered payload (signature of the original) and tampered signature.
    let mut c2 = c.clone();
    c2["sub"] = json!(uuid::Uuid::now_v7().to_string());
    bad.push((
        "payload swapped".into(),
        format!(
            "{}.{}.{}",
            parts[0],
            b64(c2.to_string().as_bytes()),
            parts[2]
        ),
    ));
    let mut sig = unb64(parts[2]);
    sig[0] ^= 1;
    bad.push((
        "signature bit flip".into(),
        format!("{}.{}.{}", parts[0], parts[1], b64(&sig)),
    ));
    bad.push(("truncated".into(), s.at[..s.at.len() - 4].to_owned()));
    bad.push(("four segments".into(), format!("{}.x", s.at)));
    bad.push(("oversized".into(), format!("{}{}", s.at, "A".repeat(5000))));
    for (name, t) in &bad {
        let r = me(&e, t).await;
        assert_eq!(r.status, 401, "{name}: accepted ({})", r.body);
        assert_eq!(r.code(), "unauthenticated", "{name}");
    }
    me(&e, &s.at).await.expect(200);
    e.finish().await;
}

/// iss/aud/exp/iat checks with valid signatures ([R12]: `exp` 0 s leeway, `iat` at most 60 s
/// in the future).
#[tokio::test]
async fn jws_claim_checks_iss_aud_exp_iat() {
    let Some(e) = Env::default().await else {
        return;
    };
    let (_, _, c) = base(&e).await;
    let kid = current_kid(&e).await;
    let h = json!({"alg": "EdDSA", "typ": "at+jwt", "kid": kid});
    let n = now();
    let with = |f: &dyn Fn(&mut Value)| {
        let mut x = c.clone();
        f(&mut x);
        x
    };
    let cases: Vec<(&str, Value, bool)> = vec![
        (
            "control: fresh",
            with(&|x| {
                x["iat"] = json!(n);
                x["exp"] = json!(n + 600);
            }),
            true,
        ),
        (
            "wrong aud",
            with(&|x| {
                x["aud"] = json!("https://other.example/api/v2");
            }),
            false,
        ),
        (
            "aud = iss",
            with(&|x| {
                x["aud"] = json!(format!("https://{DOMAIN}"));
            }),
            false,
        ),
        (
            "aud array",
            with(&|x| {
                x["aud"] = json!([format!("https://{DOMAIN}/api/v2")]);
            }),
            false,
        ),
        (
            "wrong iss",
            with(&|x| {
                x["iss"] = json!("https://evil.example");
            }),
            false,
        ),
        (
            "exp = now (0 s leeway)",
            with(&|x| {
                x["exp"] = json!(n);
            }),
            false,
        ),
        (
            "exp in the past",
            with(&|x| {
                x["iat"] = json!(n - 700);
                x["exp"] = json!(n - 100);
            }),
            false,
        ),
        (
            "exp missing",
            with(&|x| {
                x.as_object_mut().unwrap().remove("exp");
            }),
            false,
        ),
        (
            "iat 120 s in the future",
            with(&|x| {
                x["iat"] = json!(n + 120);
                x["exp"] = json!(n + 700);
            }),
            false,
        ),
        (
            "iat 30 s in the future",
            with(&|x| {
                x["iat"] = json!(n + 30);
                x["exp"] = json!(n + 600);
            }),
            true,
        ),
        (
            "exp as string",
            with(&|x| {
                x["exp"] = json!((n + 600).to_string());
            }),
            false,
        ),
    ];
    for (name, claims, ok) in cases {
        let t = sign_with_kms(&e, &h, &claims).await;
        let r = me(&e, &t).await;
        if ok {
            assert_eq!(r.status, 200, "{name}: {}", r.body);
        } else {
            assert_eq!(r.status, 401, "{name}: accepted ({})", r.body);
            assert_eq!(r.code(), "unauthenticated", "{name}");
        }
    }
    e.finish().await;
}

/// No access token, malformed schemes: 401 problem, never 500.
#[tokio::test]
async fn missing_or_malformed_authorization_is_401() {
    let Some(e) = Env::default().await else {
        return;
    };
    let (s, _, _) = base(&e).await;
    for auth in [
        None,
        Some("".to_owned()),
        Some("Bearer".to_owned()),
        Some("Bearer ".to_owned()),
        Some(format!("Basic {}", s.at)),
        Some(format!("Token {}", s.at)),
        Some(format!("Bearer  {} extra", s.at)),
    ] {
        let mut r = Req::get("/api/v2/me");
        if let Some(a) = &auth {
            r = r.header("authorization", a);
        }
        let resp = e.call(r).await;
        assert_eq!(resp.status, 401, "{auth:?}: {}", resp.body);
        assert_eq!(resp.code(), "unauthenticated");
    }
    e.finish().await;
}

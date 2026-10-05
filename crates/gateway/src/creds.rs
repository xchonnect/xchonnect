//! Provider credentials and JWT construction (spec 7.3).
//!
//! APNs uses a `.p8` ECDSA P-256 key and an ES256 provider token; FCM uses a service
//! account RSA key and an RS256 OAuth 2.0 assertion. Both are loaded from a secret
//! source (a file, or an environment variable for development), held in zeroizing
//! memory, and never formatted, logged or returned in an error (spec 13.5).
//!
//! Signing goes through `ring`, which is already in the dependency graph via rustls:
//! constant-time, BoringSSL-derived, and free of the unpatched key-recovery advisory
//! RUSTSEC-2023-0071 that affects every published version of the `rsa` crate.

use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, KeyPair, RsaKeyPair};
use serde::Deserialize;
use std::path::Path;
use xchonnect_core::b64;
use zeroize::Zeroizing;

/// Secret text loaded from a secret source. Zeroized on drop; never printed.
#[derive(Clone)]
pub struct Secret(Zeroizing<String>);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

impl Secret {
    /// Wrap text already in memory.
    pub fn new(text: String) -> Self {
        Secret(Zeroizing::new(text))
    }

    /// Read from a file (the recommended source: a mounted secret or a vault agent).
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, CredError> {
        std::fs::read_to_string(path)
            .map(Secret::new)
            .map_err(|_| CredError("secret file cannot be read"))
    }

    /// Read from an environment variable. Convenient for development; a file is
    /// preferred in production because the environment is visible to child processes.
    pub fn from_env(var: &str) -> Result<Self, CredError> {
        std::env::var(var)
            .map(Secret::new)
            .map_err(|_| CredError("secret environment variable is not set"))
    }

    /// Read a PEM from an environment variable, for hosts that can only pass settings and
    /// not mount files (a ONCE app). Some tools cannot carry a line break in a value, so the
    /// two characters `\n` are read as one.
    pub fn from_env_pem(var: &str) -> Result<Self, CredError> {
        std::env::var(var)
            .map(|text| Secret::new(unescape_newlines(&text)))
            .map_err(|_| CredError("secret environment variable is not set"))
    }

    /// Borrow the text. Callers must not log or persist it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

/// Turn the two characters `\n` into a line break.
fn unescape_newlines(text: &str) -> String {
    text.replace("\\n", "\n")
}

/// A credential or signing failure. The message is a fixed string chosen here, so no
/// key material can leak through it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredError(pub &'static str);

impl std::fmt::Display for CredError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for CredError {}

/// Signs JWT signing inputs.
pub trait Signer: Send + Sync + 'static {
    /// JWS `alg` header value.
    fn alg(&self) -> &'static str;
    /// JWS `kid` header value, if the provider requires one.
    fn key_id(&self) -> Option<&str>;
    /// Sign `signing_input` (`base64url(header) || "." || base64url(claims)`).
    fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, CredError>;
}

/// Decode a single PEM block with the given label into DER.
///
/// Total: every malformed input returns an error. The DER is zeroizing because it
/// carries the private key.
pub fn pem_to_der(pem: &str, label: &str) -> Result<Zeroizing<Vec<u8>>, CredError> {
    use base64::Engine;
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let after = pem
        .split_once(begin.as_str())
        .ok_or(CredError("PEM block not found"))?
        .1;
    let body = after
        .split_once(end.as_str())
        .ok_or(CredError("PEM block is not terminated"))?
        .0;
    let compact: String = body.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if compact.is_empty() || compact.len() > 8192 {
        return Err(CredError("PEM body length"));
    }
    base64::engine::general_purpose::STANDARD
        .decode(compact.as_bytes())
        .map(Zeroizing::new)
        .map_err(|_| CredError("PEM body is not base64"))
}

/// APNs provider-token signer: ECDSA P-256 / SHA-256, JWS fixed-width signature.
pub struct Es256Signer {
    key_id: String,
    key: EcdsaKeyPair,
    rng: SystemRandom,
}

impl std::fmt::Debug for Es256Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Es256Signer")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl Es256Signer {
    /// Load an Apple `.p8` key. `key_id` is the 10-character Key ID from the Apple
    /// developer portal and becomes the JWT `kid`.
    ///
    /// The `.p8` must be an unencrypted PKCS#8 v1 EC key that carries its public key, as
    /// Apple's downloads do; `ring` verifies the two halves agree.
    pub fn from_p8(key_id: &str, p8: &Secret) -> Result<Self, CredError> {
        if key_id.is_empty()
            || key_id.len() > 32
            || !key_id.chars().all(|c| c.is_ascii_alphanumeric())
        {
            return Err(CredError("APNs key id must be short and alphanumeric"));
        }
        let der = pem_to_der(p8.expose(), "PRIVATE KEY")?;
        let rng = SystemRandom::new();
        let key = EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &der, &rng)
            .map_err(|_| CredError("APNs .p8 is not an unencrypted PKCS#8 P-256 key"))?;
        Ok(Es256Signer {
            key_id: key_id.to_owned(),
            key,
            rng,
        })
    }

    /// SEC1 uncompressed public key, for verifying our own tokens in tests.
    pub fn public_key(&self) -> Vec<u8> {
        self.key.public_key().as_ref().to_vec()
    }
}

impl Signer for Es256Signer {
    fn alg(&self) -> &'static str {
        "ES256"
    }

    fn key_id(&self) -> Option<&str> {
        Some(&self.key_id)
    }

    fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, CredError> {
        self.key
            .sign(&self.rng, signing_input)
            .map(|s| s.as_ref().to_vec())
            .map_err(|_| CredError("ES256 signing failed"))
    }
}

/// FCM OAuth assertion signer: RSASSA-PKCS1-v1_5 / SHA-256.
pub struct Rs256Signer {
    key: RsaKeyPair,
    rng: SystemRandom,
}

impl std::fmt::Debug for Rs256Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Rs256Signer")
    }
}

impl Rs256Signer {
    /// Load the `private_key` PEM from a Google service account JSON file.
    pub fn from_pkcs8_pem(pem: &Secret) -> Result<Self, CredError> {
        let der = pem_to_der(pem.expose(), "PRIVATE KEY")?;
        let key = RsaKeyPair::from_pkcs8(&der)
            .map_err(|_| CredError("service account private_key is not a PKCS#8 RSA key"))?;
        Ok(Rs256Signer {
            key,
            rng: SystemRandom::new(),
        })
    }

    /// DER-encoded `RSAPublicKey`, for verifying our own assertions in tests.
    pub fn public_key(&self) -> Vec<u8> {
        self.key.public_key().as_ref().to_vec()
    }
}

impl Signer for Rs256Signer {
    fn alg(&self) -> &'static str {
        "RS256"
    }

    fn key_id(&self) -> Option<&str> {
        None
    }

    fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, CredError> {
        let mut sig = vec![0u8; self.key.public().modulus_len()];
        self.key
            .sign(
                &signature::RSA_PKCS1_SHA256,
                &self.rng,
                signing_input,
                &mut sig,
            )
            .map_err(|_| CredError("RS256 signing failed"))?;
        Ok(sig)
    }
}

/// Build a compact JWS: `base64url(header).base64url(claims).base64url(signature)`.
///
/// `claims` must be a JSON object; its serialisation is the only variable part.
pub fn jwt(signer: &dyn Signer, claims: &serde_json::Value) -> Result<String, CredError> {
    let header = match signer.key_id() {
        Some(kid) => serde_json::json!({ "alg": signer.alg(), "kid": kid, "typ": "JWT" }),
        None => serde_json::json!({ "alg": signer.alg(), "typ": "JWT" }),
    };
    let header = serde_json::to_vec(&header).map_err(|_| CredError("JWT header"))?;
    let claims = serde_json::to_vec(claims).map_err(|_| CredError("JWT claims"))?;
    let signing_input = format!("{}.{}", b64::encode(&header), b64::encode(&claims));
    let sig = signer.sign(signing_input.as_bytes())?;
    Ok(format!("{signing_input}.{}", b64::encode(&sig)))
}

/// A Google service account, parsed from its JSON key file.
///
/// `token_uri` is checked against [`GOOGLE_TOKEN_URI`]: a tampered key file must not be
/// able to redirect a signed assertion (a bearer credential) to another host (T21).
#[derive(Debug)]
pub struct ServiceAccount {
    /// `client_email`, the assertion `iss`.
    pub client_email: String,
    /// `project_id`, used in the FCM send URL.
    pub project_id: String,
}

/// The only accepted OAuth 2.0 token endpoint.
pub const GOOGLE_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";

#[derive(Deserialize)]
struct ServiceAccountJson {
    #[serde(default)]
    r#type: String,
    #[serde(default)]
    client_email: String,
    #[serde(default)]
    project_id: String,
    #[serde(default)]
    token_uri: String,
    #[serde(default)]
    private_key: String,
}

impl ServiceAccount {
    /// Parse a service account JSON key and build its RS256 signer.
    pub fn parse(json: &Secret) -> Result<(Self, Rs256Signer), CredError> {
        let p: ServiceAccountJson =
            serde_json::from_str(json.expose()).map_err(|_| CredError("service account JSON"))?;
        if p.r#type != "service_account" {
            return Err(CredError("not a service account key"));
        }
        if !p.token_uri.is_empty() && p.token_uri != GOOGLE_TOKEN_URI {
            return Err(CredError("service account token_uri is not the Google one"));
        }
        if p.client_email.is_empty() || p.client_email.len() > 320 {
            return Err(CredError("service account client_email"));
        }
        if !project_id_is_valid(&p.project_id) {
            return Err(CredError("service account project_id"));
        }
        let signer = Rs256Signer::from_pkcs8_pem(&Secret::new(p.private_key))?;
        Ok((
            ServiceAccount {
                client_email: p.client_email,
                project_id: p.project_id,
            },
            signer,
        ))
    }
}

/// Whether a Google project id is safe to place in a URL path.
pub fn project_id_is_valid(id: &str) -> bool {
    (4..=63).contains(&id.len())
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
pub(crate) mod tests {
    use super::*;

    /// A freshly generated P-256 `.p8`-shaped PEM plus its Key ID.
    pub(crate) fn test_p8() -> Secret {
        let rng = SystemRandom::new();
        let doc = EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .unwrap();
        pem("PRIVATE KEY", doc.as_ref())
    }

    pub(crate) fn pem(label: &str, der: &[u8]) -> Secret {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        let lines: Vec<String> = b64
            .as_bytes()
            .chunks(64)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect();
        Secret::new(format!(
            "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
            lines.join("\n")
        ))
    }

    #[test]
    fn a_pem_with_escaped_line_breaks_signs_like_the_original() {
        let original = test_p8();
        let escaped = original.expose().trim_end().replace('\n', "\\n");
        assert!(!escaped.contains('\n'));
        let restored = Secret::new(unescape_newlines(&escaped));
        let a = Es256Signer::from_p8("KEYID12345", &original).unwrap();
        let b = Es256Signer::from_p8("KEYID12345", &restored).unwrap();
        assert_eq!(a.public_key(), b.public_key());
    }

    /// Verify a compact JWS with the signer's own public key.
    pub(crate) fn verify_es256(public_key: &[u8], token: &str) -> bool {
        let Some((input, sig)) = token.rsplit_once('.') else {
            return false;
        };
        let Ok(sig) = b64::decode(sig) else {
            return false;
        };
        signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, public_key)
            .verify(input.as_bytes(), &sig)
            .is_ok()
    }

    /// Decode the header or claims segment of a compact JWS.
    pub(crate) fn segment(token: &str, n: usize) -> serde_json::Value {
        let part = token.split('.').nth(n).unwrap();
        serde_json::from_slice(&b64::decode(part).unwrap()).unwrap()
    }

    #[test]
    fn secrets_never_print_themselves() {
        let s = Secret::new("super-secret-key-material".into());
        assert!(!format!("{s:?}").contains("secret-key"));
        assert_eq!(format!("{s:?}"), "Secret([redacted])");
        assert_eq!(s.expose(), "super-secret-key-material");
        let signer = Es256Signer::from_p8("ABC1234567", &test_p8()).unwrap();
        assert!(!format!("{signer:?}").contains("PRIVATE"));
        assert!(format!("{signer:?}").contains("ABC1234567"));
    }

    #[test]
    fn es256_tokens_verify_and_carry_the_key_id() {
        let p8 = test_p8();
        let signer = Es256Signer::from_p8("KEYID12345", &p8).unwrap();
        let token = jwt(
            &signer,
            &serde_json::json!({ "iss": "TEAMID1234", "iat": 1_790_000_000u64 }),
        )
        .unwrap();
        assert_eq!(token.split('.').count(), 3);
        assert_eq!(
            segment(&token, 0),
            serde_json::json!({ "alg": "ES256", "kid": "KEYID12345", "typ": "JWT" })
        );
        assert_eq!(
            segment(&token, 1),
            serde_json::json!({ "iss": "TEAMID1234", "iat": 1_790_000_000u64 })
        );
        assert!(verify_es256(&signer.public_key(), &token));
        // A different key must not verify.
        let other = Es256Signer::from_p8("KEYID12345", &test_p8()).unwrap();
        assert!(!verify_es256(&other.public_key(), &token));
        // And a tampered claim must not verify.
        let mut parts: Vec<&str> = token.split('.').collect();
        let forged = b64::encode(br#"{"iss":"OTHERTEAM","iat":1790000000}"#);
        parts[1] = &forged;
        assert!(!verify_es256(&signer.public_key(), &parts.join(".")));
    }

    #[test]
    fn malformed_credentials_are_rejected_without_leaking() {
        let bad_pem = [
            ("", "PEM block not found"),
            ("-----BEGIN PRIVATE KEY-----", "PEM block is not terminated"),
            (
                "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----",
                "PEM body length",
            ),
            (
                "-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----",
                "PEM body is not base64",
            ),
        ];
        for (pem, msg) in bad_pem {
            assert_eq!(
                pem_to_der(pem, "PRIVATE KEY"),
                Err(CredError(msg)),
                "{pem:?}"
            );
        }
        // Valid PEM, but not an EC key.
        assert!(Es256Signer::from_p8("K1", &pem("PRIVATE KEY", &[1, 2, 3])).is_err());
        // Bad key ids never reach the signer.
        for kid in ["", "has space", &"x".repeat(33)] {
            assert!(Es256Signer::from_p8(kid, &test_p8()).is_err(), "{kid:?}");
        }
        assert!(
            Rs256Signer::from_pkcs8_pem(&test_p8()).is_err(),
            "EC key is not RSA"
        );
    }

    #[test]
    fn service_account_json_is_validated() {
        let p8 = test_p8();
        let key = p8.expose().replace('\n', "\\n");
        let make = |extra: &str| {
            Secret::new(format!(
                "{{\"type\":\"service_account\",\"client_email\":\"a@b.iam.gserviceaccount.com\",\
                  \"project_id\":\"my-project\",\"private_key\":\"{key}\"{extra}}}"
            ))
        };
        // An EC key is not an RSA key: parsing gets that far and then refuses.
        assert_eq!(
            ServiceAccount::parse(&make("")).map(|_| ()),
            Err(CredError(
                "service account private_key is not a PKCS#8 RSA key"
            ))
        );
        assert_eq!(
            ServiceAccount::parse(&make(",\"token_uri\":\"https://evil.example/token\""))
                .map(|_| ()),
            Err(CredError("service account token_uri is not the Google one"))
        );
        assert_eq!(
            ServiceAccount::parse(&Secret::new("{}".into())).map(|_| ()),
            Err(CredError("not a service account key"))
        );
        assert_eq!(
            ServiceAccount::parse(&Secret::new("not json".into())).map(|_| ()),
            Err(CredError("service account JSON"))
        );
    }

    #[test]
    fn project_ids_are_path_safe() {
        for ok in ["my-project", "abcd", "p1234567890"] {
            assert!(project_id_is_valid(ok), "{ok}");
        }
        for bad in [
            "",
            "abc",
            "a/b/c",
            "../x",
            "UPPER",
            "with space",
            &"x".repeat(64),
        ] {
            assert!(!project_id_is_valid(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_signer_without_a_key_id_omits_kid() {
        let signer = TestSigner::new("RS256");
        let token = jwt(&signer, &serde_json::json!({ "iss": "sa@x.iam" })).unwrap();
        assert_eq!(
            segment(&token, 0),
            serde_json::json!({ "alg": "RS256", "typ": "JWT" })
        );
        assert_eq!(
            signer.signed_inputs(),
            vec![token.rsplit_once('.').unwrap().0.to_owned()]
        );
    }
}

/// Signer double: records what it was asked to sign and returns a fixed signature.
/// Lets the APNs and FCM request, caching and retry paths be tested with no vendor key.
#[derive(Debug)]
pub struct TestSigner {
    alg: &'static str,
    key_id: Option<String>,
    /// Signing inputs seen, in order.
    inputs: std::sync::Mutex<Vec<String>>,
    /// Set to fail every signature.
    pub broken: bool,
}

impl TestSigner {
    /// Signer for `alg` with no key id.
    pub fn new(alg: &'static str) -> Self {
        TestSigner {
            alg,
            key_id: None,
            inputs: std::sync::Mutex::default(),
            broken: false,
        }
    }

    /// Signer for `alg` that advertises `kid`.
    pub fn with_key_id(alg: &'static str, kid: &str) -> Self {
        TestSigner {
            key_id: Some(kid.to_owned()),
            ..TestSigner::new(alg)
        }
    }

    /// Signer that always fails.
    pub fn broken(alg: &'static str) -> Self {
        TestSigner {
            broken: true,
            ..TestSigner::new(alg)
        }
    }

    /// Signing inputs seen so far.
    pub fn signed_inputs(&self) -> Vec<String> {
        crate::lock(&self.inputs).clone()
    }
}

impl Signer for TestSigner {
    fn alg(&self) -> &'static str {
        self.alg
    }

    fn key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }

    fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, CredError> {
        if self.broken {
            return Err(CredError("test signer is broken"));
        }
        crate::lock(&self.inputs).push(String::from_utf8_lossy(signing_input).into_owned());
        // Not a real signature: these tests assert request shape, not cryptography.
        Ok(xchonnect_core::crypto::sha256_parts(&[signing_input]).to_vec())
    }
}

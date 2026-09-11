//! HMAC challenge-response authentication shared by every agent.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn sign(key: &[u8], payload: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts keys of any length");
    mac.update(payload);
    hex::encode(mac.finalize().into_bytes())
}

/// Sign the server challenge and device identifier using the enrolled token.
///
/// The challenge and system ID are concatenated without a separator to preserve
/// the existing v1 authentication wire format.
#[uniffi::export]
pub fn generate_auth_signature(token: String, challenge: String, system_id: String) -> String {
    sign(
        token.as_bytes(),
        format!("{challenge}{system_id}").as_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use super::{generate_auth_signature, sign};

    #[test]
    fn matches_rfc_4231_sha256_vector() {
        assert_eq!(
            sign(&[0x0b; 20], b"Hi There"),
            "b0344c61d8db38535ca8afceaf0bf12b\
             881dc200c9833da726e9376c2e32cff7"
                .replace(char::is_whitespace, "")
        );
    }

    #[test]
    fn matches_guardian_v1_golden_vector() {
        assert_eq!(
            generate_auth_signature(
                "guardian-test-token".to_owned(),
                "0123456789abcdef".to_owned(),
                "device-1234".to_owned(),
            ),
            "d874f20602ae4569b07f801b1a97953acc0b3ab47bc16dcbca649ff19f55514a"
        );
    }
}

//! Release asset verification shared by Linux and Windows self-updaters.

use sha2::{Digest, Sha256};

pub fn verify_release_asset(asset_bytes: &[u8], expected_checksum: &str) -> Result<(), String> {
    let mut hasher = Sha256::new();
    hasher.update(asset_bytes);
    let result = hasher.finalize();
    let calculated_checksum = hex::encode(result);

    let expected_checksum = expected_checksum
        .trim()
        .split_whitespace()
        .next()
        .unwrap_or("");
    if calculated_checksum.eq_ignore_ascii_case(expected_checksum) {
        Ok(())
    } else {
        Err(format!(
            "Checksum verification failed. Expected: {expected_checksum}, Calculated: {calculated_checksum}"
        ))
    }
}

pub fn is_valid_release_version(version: &str) -> bool {
    let version = version.trim();
    if version.is_empty() || version.len() > 64 {
        return false;
    }
    let Some(tag) = version.strip_prefix('v') else {
        return false;
    };
    tag.chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_'))
}

pub fn is_valid_github_repo(repo: &str) -> bool {
    let repo = repo.trim();
    if repo.is_empty() || repo.len() > 128 {
        return false;
    }
    let Some((owner, name)) = repo.split_once('/') else {
        return false;
    };
    if owner.is_empty() || name.is_empty() {
        return false;
    }
    let valid_segment = |segment: &str| {
        !segment.is_empty()
            && segment != "."
            && segment != ".."
            && !segment.starts_with('.')
            && segment
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_'))
    };
    valid_segment(owner) && valid_segment(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_expected_release_tags() {
        assert!(is_valid_release_version("v0.1.0"));
        assert!(is_valid_release_version("v1.2.3-rc1"));
    }

    #[test]
    fn rejects_unsafe_release_tags() {
        assert!(!is_valid_release_version(""));
        assert!(!is_valid_release_version("0.1.0"));
        assert!(!is_valid_release_version("v../etc/passwd"));
        assert!(!is_valid_release_version("vtag/with/slash"));
    }

    #[test]
    fn accepts_org_and_legacy_github_repos() {
        assert!(is_valid_github_repo(
            "Guardian-Parental-Controls/agent-linux"
        ));
        assert!(is_valid_github_repo("pantherale0/timekpr-webui"));
    }

    #[test]
    fn rejects_unsafe_github_repos() {
        assert!(!is_valid_github_repo(""));
        assert!(!is_valid_github_repo("owner-only"));
        assert!(!is_valid_github_repo("owner/repo/extra"));
        assert!(!is_valid_github_repo("../timekpr-webui"));
    }

    #[test]
    fn verifies_known_checksum() {
        let asset = b"guardian-release-fixture";
        let expected = "c8b1c2f0e6d3c8d1a0f0e6d3c8d1a0f0e6d3c8d1a0f0e6d3c8d1a0f0e6d3c8d1";
        let mut hasher = Sha256::new();
        hasher.update(asset);
        let digest = hex::encode(hasher.finalize());
        verify_release_asset(asset, &digest).expect("computed digest should verify");
        assert!(verify_release_asset(asset, expected).is_err());
    }
}

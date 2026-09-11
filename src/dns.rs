//! DNS policy helpers shared by native and Android agents.

use std::collections::HashSet;

use hickory_proto::op::{Message, ResponseCode};

pub fn domain_is_blocked(domain_name: &str, blocked_domains: &HashSet<String>) -> bool {
    let mut candidate = domain_name.trim_end_matches('.').to_ascii_lowercase();
    loop {
        if blocked_domains.contains(&candidate) {
            return true;
        }
        let Some((_, remainder)) = candidate.split_once('.') else {
            break;
        };
        candidate = remainder.to_owned();
    }
    false
}

pub fn domain_is_allowed(domain_name: &str, allowed_domains: &HashSet<String>) -> bool {
    domain_is_blocked(domain_name, allowed_domains)
}

pub fn registrable_domain(domain_name: &str) -> String {
    let candidate = domain_name.trim_end_matches('.').to_ascii_lowercase();
    let parts: Vec<&str> = candidate
        .split('.')
        .filter(|part| !part.is_empty())
        .collect();
    if parts.len() >= 2 {
        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        candidate
    }
}

pub fn build_blocked_response(query_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let query = Message::from_vec(query_bytes)
        .map_err(|error| format!("failed to parse DNS query: {error}"))?;

    let mut response = Message::error_msg(
        query.metadata.id,
        query.metadata.op_code,
        ResponseCode::NXDomain,
    );
    response.metadata.recursion_desired = query.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.metadata.checking_disabled = query.metadata.checking_disabled;
    response.queries.clone_from(&query.queries);

    response
        .to_vec()
        .map_err(|error| format!("failed to serialize blocked response: {error}"))
}

#[uniffi::export]
pub fn check_and_build_blocked_response(
    query_bytes: Vec<u8>,
    blocked_domains: Vec<String>,
    allowed_domains: Vec<String>,
) -> Option<Vec<u8>> {
    let blocked_set: HashSet<String> = blocked_domains
        .into_iter()
        .map(|domain| domain.to_ascii_lowercase())
        .collect();
    let allowed_set: HashSet<String> = allowed_domains
        .into_iter()
        .map(|domain| domain.to_ascii_lowercase())
        .collect();

    let query = Message::from_vec(&query_bytes).ok()?;
    let should_block = query.queries.iter().any(|entry| {
        let domain = entry.name().to_ascii();
        domain_is_blocked(&domain, &blocked_set) && !domain_is_allowed(&domain, &allowed_set)
    });

    should_block
        .then(|| build_blocked_response(&query_bytes).ok())
        .flatten()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{domain_is_allowed, domain_is_blocked, registrable_domain};

    #[test]
    fn parent_domain_matches_subdomains_case_insensitively() {
        let blocked = HashSet::from(["example.com".to_owned()]);
        assert!(domain_is_blocked("API.Example.COM.", &blocked));
        assert!(!domain_is_blocked("example.net.", &blocked));
    }

    #[test]
    fn allowlist_uses_the_same_parent_matching() {
        let allowed = HashSet::from(["safe.example.com".to_owned()]);
        assert!(domain_is_allowed("www.safe.example.com.", &allowed));
    }

    #[test]
    fn registrable_domain_preserves_v1_last_two_label_behavior() {
        assert_eq!(registrable_domain("api.example.com."), "example.com");
    }
}

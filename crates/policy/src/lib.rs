use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fs, path::Path};

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("failed to read policy file: {0}")]
    Read(#[from] std::io::Error),
    #[error("invalid policy yaml: {0}")]
    Parse(#[from] serde_yaml::Error),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyFile {
    pub firewall: FirewallPolicy,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FirewallPolicy {
    #[serde(default)]
    pub allow_tools: HashSet<String>,
    #[serde(default)]
    pub deny_tools: HashSet<String>,
    #[serde(default)]
    pub allowed_paths: Vec<String>,
    #[serde(default = "default_max_body")]
    pub max_body_bytes: usize,
    #[serde(default)]
    pub require_origin: bool,
    #[serde(default)]
    pub allowed_origins: HashSet<String>,
    #[serde(default)]
    pub require_signature: bool,
    #[serde(default = "default_rate")]
    pub rate_limit_per_minute: u32,
    #[serde(default)]
    pub sign_responses: bool,
}

fn default_max_body() -> usize {
    64 * 1024
}
fn default_rate() -> u32 {
    120
}

#[derive(Debug, Clone)]
pub struct RequestContext {
    pub method: String,
    pub path: Option<String>,
    pub origin: Option<String>,
    pub body_len: usize,
    pub has_valid_signature: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Decision {
    pub allow: bool,
    pub reason: String,
    pub at: String,
}

impl PolicyFile {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, PolicyError> {
        let data = fs::read_to_string(path)?;
        Ok(serde_yaml::from_str(&data)?)
    }

    pub fn evaluate(&self, req: &RequestContext) -> Decision {
        let policy = &self.firewall;

        if req.body_len > policy.max_body_bytes {
            return deny("body_too_large");
        }
        if policy.require_origin {
            match req.origin.as_ref() {
                Some(origin) if policy.allowed_origins.contains(origin) => {}
                _ => return deny("origin_not_allowed"),
            }
        }
        if policy.require_signature && !req.has_valid_signature {
            return deny("signature_missing_or_invalid");
        }
        if policy.deny_tools.contains(&req.method) {
            return deny("tool_explicitly_denied");
        }
        if !policy.allow_tools.is_empty() && !policy.allow_tools.contains(&req.method) {
            return deny("tool_not_in_allowlist");
        }
        if let Some(path) = req.path.as_ref() {
            if !policy.allowed_paths.is_empty()
                && !policy.allowed_paths.iter().any(|p| path.starts_with(p))
            {
                return deny("path_not_allowed");
            }
        }

        allow("policy_pass")
    }
}

fn allow(reason: &str) -> Decision {
    Decision {
        allow: true,
        reason: reason.to_owned(),
        at: Utc::now().to_rfc3339(),
    }
}

fn deny(reason: &str) -> Decision {
    Decision {
        allow: false,
        reason: reason.to_owned(),
        at: Utc::now().to_rfc3339(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> PolicyFile {
        serde_yaml::from_str(
            r#"firewall:
  allow_tools: ["tools.call"]
  deny_tools: ["tools.delete"]
  allowed_paths: ["/safe"]
  require_origin: true
  allowed_origins: ["agent://trusted"]
  require_signature: true
  max_body_bytes: 100
  rate_limit_per_minute: 5
  sign_responses: true
"#,
        )
        .unwrap()
    }

    #[test]
    fn blocks_untrusted_origin() {
        let p = policy();
        let d = p.evaluate(&RequestContext {
            method: "tools.call".into(),
            path: Some("/safe/file".into()),
            origin: Some("agent://evil".into()),
            body_len: 10,
            has_valid_signature: true,
        });
        assert!(!d.allow);
    }
}

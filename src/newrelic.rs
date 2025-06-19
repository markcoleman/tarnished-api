use std::env;
use tracing::info;

/// New Relic configuration
#[derive(Clone, Debug)]
pub struct NewRelicConfig {
    pub enabled: bool,
    pub api_key: Option<String>,
    pub endpoint: String,
    pub service_name: String,
    pub service_version: String,
    pub environment: String,
}

impl Default for NewRelicConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            api_key: None,
            endpoint: "https://log-api.newrelic.com/log/v1".to_string(),
            service_name: "tarnished-api".to_string(),
            service_version: "0.1.0".to_string(),
            environment: "development".to_string(),
        }
    }
}

impl NewRelicConfig {
    pub fn from_env() -> Self {
        let api_key = env::var("NEW_RELIC_LICENSE_KEY").ok();
        let enabled = api_key.is_some() && env::var("NEW_RELIC_ENABLED").unwrap_or_else(|_| "true".to_string()) == "true";
        
        Self {
            enabled,
            api_key,
            endpoint: env::var("NEW_RELIC_LOG_ENDPOINT")
                .unwrap_or_else(|_| "https://log-api.newrelic.com/log/v1".to_string()),
            service_name: env::var("NEW_RELIC_SERVICE_NAME")
                .unwrap_or_else(|_| "tarnished-api".to_string()),
            service_version: env::var("NEW_RELIC_SERVICE_VERSION")
                .unwrap_or_else(|_| env!("CARGO_PKG_VERSION").to_string()),
            environment: env::var("NEW_RELIC_ENVIRONMENT")
                .unwrap_or_else(|_| "development".to_string()),
        }
    }
}

/// Initialize New Relic - for now this is a simplified version that just logs the configuration
pub fn init_tracing(config: &NewRelicConfig) -> Result<(), Box<dyn std::error::Error>> {
    if !config.enabled {
        info!("New Relic integration disabled");
        return Ok(());
    }

    info!(
        message = "New Relic integration initialized",
        service_name = %config.service_name,
        service_version = %config.service_version,
        environment = %config.environment,
        endpoint = %config.endpoint,
    );
    
    Ok(())
}

/// Shutdown - placeholder for future implementation
pub fn shutdown_tracing() {
    info!("New Relic integration shutdown");
}

/// Enhanced tracing fields for New Relic correlation
pub struct NewRelicFields {
    pub request_id: String,
    pub user_agent: Option<String>,
    pub ip_address: String,
    pub method: String,
    pub path: String,
    pub status_code: Option<u16>,
}

impl NewRelicFields {
    pub fn from_request(req: &actix_web::HttpRequest) -> Self {
        Self {
            request_id: req
                .headers()
                .get("x-request-id")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("unknown")
                .to_string(),
            user_agent: req
                .headers()
                .get("user-agent")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string()),
            ip_address: req
                .connection_info()
                .peer_addr()
                .unwrap_or("unknown")
                .to_string(),
            method: req.method().to_string(),
            path: req.path().to_string(),
            status_code: None,
        }
    }

    pub fn with_status_code(mut self, status: u16) -> Self {
        self.status_code = Some(status);
        self
    }
}

/// Sensitive data patterns to redact
static SENSITIVE_PATTERNS: &[&str] = &[
    r#"(?i)"password":\s*"[^"]+""#,
    r#"(?i)"token":\s*"[^"]+""#,
    r#"(?i)"api[_-]?key":\s*"[^"]+""#,
    r#"(?i)"secret":\s*"[^"]+""#,
    r#"(?i)"authorization":\s*"[^"]+""#,
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", // Email addresses
    r"\b\d{3}-\d{2}-\d{4}\b", // SSN pattern
    r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b", // Credit card pattern
];

/// Redact sensitive data from log messages
pub fn redact_sensitive_data(input: &str) -> String {
    let mut result = input.to_string();
    
    for pattern in SENSITIVE_PATTERNS {
        if let Ok(re) = regex::Regex::new(pattern) {
            result = re.replace_all(&result, r#""[FIELD]": "[REDACTED]""#).to_string();
        }
    }
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sensitive_data_redaction() {
        let input = r#"{"password": "secret123", "email": "user@example.com", "token": "abc123"}"#;
        let redacted = redact_sensitive_data(input);
        
        assert!(!redacted.contains("secret123"));
        assert!(!redacted.contains("user@example.com"));
        assert!(!redacted.contains("abc123"));
        assert!(redacted.contains("[REDACTED]"));
    }

    #[test]
    fn test_config_from_env() {
        unsafe {
            env::set_var("NEW_RELIC_LICENSE_KEY", "test-key");
            env::set_var("NEW_RELIC_SERVICE_NAME", "test-service");
        }
        
        let config = NewRelicConfig::from_env();
        
        assert!(config.enabled);
        assert_eq!(config.api_key, Some("test-key".to_string()));
        assert_eq!(config.service_name, "test-service");
        
        unsafe {
            env::remove_var("NEW_RELIC_LICENSE_KEY");
            env::remove_var("NEW_RELIC_SERVICE_NAME");
        }
    }
}
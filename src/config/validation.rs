use std::fmt;

/// Configuration validation error
#[derive(Debug, Clone)]
pub struct ConfigError {
    pub field: String,
    pub message: String,
}

impl ConfigError {
    pub fn invalid(field: &str, message: &str) -> Self {
        Self {
            field: field.to_string(),
            message: message.to_string(),
        }
    }

    pub fn load_error(message: &str) -> Self {
        Self {
            field: "config".to_string(),
            message: message.to_string(),
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Configuration error in '{}': {}", self.field, self.message)
    }
}

impl std::error::Error for ConfigError {}

impl From<nexus_state::error::GossipError> for ConfigError {
    fn from(err: nexus_state::error::GossipError) -> Self {
        ConfigError::invalid("gossip", &err.to_string())
    }
}

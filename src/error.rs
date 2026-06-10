use std::fmt;

/// Errors that can occur in PQ-Aura operations.
///
/// This enum represents all possible errors that can occur when using PQ-Aura.
/// All errors are safe to propagate and do not leak sensitive information.
#[derive(Debug)]
pub enum AuraError {
    /// Cryptographic operation failed
    CryptoError(String),
    
    /// Serialization/deserialization failed
    SerializationError(String),
    
    /// Key has invalid length
    KeyLengthError(String),
    
    /// Invalid state for the requested operation
    InvalidState(String),
    
    /// Network/IO error (for future use)
    NetworkError(String),
    
    /// Authentication failed
    AuthenticationError(String),
    
    /// Message too old or too far out of order
    MessageOrderError(String),
}

impl fmt::Display for AuraError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuraError::CryptoError(msg) => write!(f, "Cryptographic Error: {}", msg),
            AuraError::SerializationError(msg) => write!(f, "Serialization Error: {}", msg),
            AuraError::KeyLengthError(msg) => write!(f, "Key Length Error: {}", msg),
            AuraError::InvalidState(msg) => write!(f, "Invalid State Error: {}", msg),
            AuraError::NetworkError(msg) => write!(f, "Network Error: {}", msg),
            AuraError::AuthenticationError(msg) => write!(f, "Authentication Error: {}", msg),
            AuraError::MessageOrderError(msg) => write!(f, "Message Order Error: {}", msg),
        }
    }
}

impl std::error::Error for AuraError {}

impl From<&str> for AuraError {
    fn from(s: &str) -> Self {
        AuraError::CryptoError(s.to_string())
    }
}

impl From<String> for AuraError {
    fn from(s: String) -> Self {
        AuraError::CryptoError(s)
    }
}

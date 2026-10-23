//! Errors a remote call can produce, and which of them are worth retrying.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// JSON-RPC 2.0 "method not found".
///
/// A zakura listener with cookie auth disabled on Mainnet or Testnet removes every method that is
/// not on its unauthenticated allow list, so this is also what a restricted listener answers for a
/// method that needs credentials.
pub const METHOD_NOT_FOUND: i64 = -32601;

/// zcashd legacy code: the node is still warming up.
pub const IN_WARMUP: i64 = -28;

/// The error object the node returns inside a JSON-RPC response.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct RpcErrorObject {
    /// JSON-RPC or zcashd legacy error code.
    pub code: i64,
    /// Human readable message.
    pub message: String,
    /// Extra data, rarely set by zakura.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// Why a remote call failed.
#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    /// The client could not be built from its configuration.
    #[error("invalid remote RPC configuration: {0}")]
    Config(String),

    /// The request never produced an HTTP response: DNS, connect, TLS, or a read error.
    #[error("{method}: request failed: {source}")]
    Transport {
        /// Method that was being called.
        method: String,
        /// Underlying client error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// The node accepted the connection and closed it without answering.
    ///
    /// zakura does this when cookie auth is on and the credentials are wrong, so the hint names
    /// that case.
    #[error("{method}: node closed the connection without a response ({hint})")]
    ConnectionClosed {
        /// Method that was being called.
        method: String,
        /// Most likely cause.
        hint: &'static str,
    },

    /// No response within the method's timeout.
    #[error("{method}: timed out after {timeout:?}")]
    Timeout {
        /// Method that was being called.
        method: String,
        /// Timeout that elapsed.
        timeout: Duration,
    },

    /// HTTP 401 or 403.
    #[error("{method}: node rejected the credentials (HTTP {status})")]
    Unauthorized {
        /// Method that was being called.
        method: String,
        /// HTTP status code.
        status: u16,
    },

    /// Any other non-2xx HTTP status.
    #[error("{method}: node returned HTTP {status}: {body}")]
    Http {
        /// Method that was being called.
        method: String,
        /// HTTP status code.
        status: u16,
        /// Start of the response body.
        body: String,
    },

    /// The node answered with a JSON-RPC error object.
    #[error("{method}: node returned error {code}: {message}")]
    Rpc {
        /// Method that was being called.
        method: String,
        /// Error code from the node.
        code: i64,
        /// Message from the node.
        message: String,
        /// Extra data from the node.
        data: Option<Value>,
    },

    /// The response was not a JSON-RPC envelope for this request.
    #[error("{method}: malformed response: {detail}")]
    Protocol {
        /// Method that was being called.
        method: String,
        /// What was wrong.
        detail: String,
    },

    /// The `result` field did not match the expected type.
    #[error("{method}: could not decode result: {source}")]
    Decode {
        /// Method that was being called.
        method: String,
        /// Serde error.
        #[source]
        source: serde_json::Error,
    },
}

impl RpcError {
    /// Method the failed call was for, when the error is tied to a call.
    pub fn method(&self) -> Option<&str> {
        match self {
            Self::Config(_) => None,
            Self::Transport { method, .. }
            | Self::ConnectionClosed { method, .. }
            | Self::Timeout { method, .. }
            | Self::Unauthorized { method, .. }
            | Self::Http { method, .. }
            | Self::Rpc { method, .. }
            | Self::Protocol { method, .. }
            | Self::Decode { method, .. } => Some(method),
        }
    }

    /// Error code from the node, when the node answered with an error object.
    pub const fn rpc_code(&self) -> Option<i64> {
        match self {
            Self::Rpc { code, .. } => Some(*code),
            _ => None,
        }
    }

    /// True when the node does not serve this method, including on a restricted listener.
    pub fn is_method_not_found(&self) -> bool {
        self.rpc_code() == Some(METHOD_NOT_FOUND)
    }

    /// True when the same request may succeed if sent again.
    ///
    /// Every call the client makes is idempotent on the node, so a retry can never double an
    /// effect. What it must not do is retry an answer that will not change: a node error other
    /// than warm-up, a bad request, a decode failure.
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Transport { .. } | Self::ConnectionClosed { .. } | Self::Timeout { .. } => true,
            Self::Http { status, .. } => matches!(status, 429 | 502 | 503 | 504),
            Self::Rpc { code, .. } => *code == IN_WARMUP,
            Self::Config(_)
            | Self::Unauthorized { .. }
            | Self::Protocol { .. }
            | Self::Decode { .. } => false,
        }
    }

    pub(crate) fn from_object(method: &str, object: RpcErrorObject) -> Self {
        Self::Rpc {
            method: method.to_owned(),
            code: object.code,
            message: object.message,
            data: object.data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http(status: u16) -> RpcError {
        RpcError::Http { method: "m".into(), status, body: String::new() }
    }

    fn rpc(code: i64) -> RpcError {
        RpcError::from_object("m", RpcErrorObject { code, message: String::new(), data: None })
    }

    #[test]
    fn retry_classification() {
        assert!(http(503).is_retryable());
        assert!(http(429).is_retryable());
        assert!(!http(500).is_retryable());
        assert!(!http(400).is_retryable());
        assert!(rpc(IN_WARMUP).is_retryable());
        assert!(!rpc(-8).is_retryable());
        assert!(!rpc(METHOD_NOT_FOUND).is_retryable());
        assert!(rpc(METHOD_NOT_FOUND).is_method_not_found());
        assert!(
            RpcError::Timeout { method: "m".into(), timeout: Duration::from_secs(1) }
                .is_retryable()
        );
        assert!(!RpcError::Unauthorized { method: "m".into(), status: 401 }.is_retryable());
        assert!(!RpcError::Config("x".into()).is_retryable());
    }
}

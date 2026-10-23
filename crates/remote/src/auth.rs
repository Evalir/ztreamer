//! Credentials for the node's JSON-RPC listener.

use std::path::{Path, PathBuf};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use http::HeaderValue;

use crate::RpcError;

/// How the client authenticates to the node.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Auth {
    /// No `Authorization` header. Works against a listener with cookie auth disabled, which on
    /// Mainnet and Testnet serves only the restricted method set.
    #[default]
    None,
    /// zakura's cookie file, `.cookie` under the node's cache directory.
    ///
    /// The node rewrites it on every start. The client reads it when built and reads it again
    /// after a rejected call, so a node restart does not need a client restart.
    Cookie(PathBuf),
    /// Fixed user and password, sent as HTTP basic auth.
    Basic {
        /// User name. zakura ignores it and checks only the password.
        user: String,
        /// Password.
        password: String,
    },
}

impl Auth {
    /// Builds the `Authorization` header value, reading the cookie file if there is one.
    pub(crate) fn header(&self) -> Result<Option<HeaderValue>, RpcError> {
        match self {
            Self::None => Ok(None),
            Self::Cookie(path) => read_cookie(path).map(|cookie| Some(basic(&cookie))),
            Self::Basic { user, password } => {
                if user.contains(':') {
                    return Err(RpcError::Config("basic auth user must not contain ':'".into()));
                }
                Ok(Some(basic(&format!("{user}:{password}"))))
            }
        }
    }

    pub(crate) const fn is_cookie(&self) -> bool {
        matches!(self, Self::Cookie(_))
    }
}

/// Reads a zakura cookie file and returns its `user:secret` line.
///
/// The file holds one line, `__cookie__:<secret>`. The node compares only the part after the
/// colon, so the whole line is what goes into the basic auth header.
pub fn read_cookie(path: &Path) -> Result<String, RpcError> {
    let contents = std::fs::read_to_string(path).map_err(|error| {
        RpcError::Config(format!("cannot read cookie file {}: {error}", path.display()))
    })?;
    let line = contents.trim();
    if line.is_empty() || !line.contains(':') {
        return Err(RpcError::Config(format!(
            "cookie file {} does not hold a user:secret line",
            path.display()
        )));
    }
    Ok(line.to_owned())
}

fn basic(credentials: &str) -> HeaderValue {
    let encoded = STANDARD.encode(credentials.as_bytes());
    HeaderValue::try_from(format!("Basic {encoded}")).expect("base64 is a valid header value")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_file_becomes_basic_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".cookie");
        std::fs::write(&path, "__cookie__:s3cret\n").unwrap();
        let header = Auth::Cookie(path).header().unwrap().unwrap();
        assert_eq!(
            header.to_str().unwrap(),
            format!("Basic {}", STANDARD.encode(b"__cookie__:s3cret"))
        );
    }

    #[test]
    fn cookie_file_must_exist_and_have_a_colon() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");
        assert!(matches!(Auth::Cookie(missing).header(), Err(RpcError::Config(_))));
        let bad = dir.path().join("bad");
        std::fs::write(&bad, "nocolon").unwrap();
        assert!(matches!(Auth::Cookie(bad).header(), Err(RpcError::Config(_))));
    }

    #[test]
    fn basic_auth_rejects_colon_in_user() {
        let auth = Auth::Basic { user: "a:b".into(), password: "p".into() };
        assert!(matches!(auth.header(), Err(RpcError::Config(_))));
        assert!(Auth::None.header().unwrap().is_none());
    }
}

use crate::{InternalError, SignatureError};

/// Ed25519 contexts as used by Ed25519ctx and Ed25519ph.
///
/// Contexts are domain separator strings that can be used to separate uses of
/// the protocol between different protocols (which is very hard to reliably do
/// otherwise) and between different uses within the same protocol.
///
/// To create a context, call either of the following:
///
/// - [`SigningKey::with_context`](crate::SigningKey::with_context)
/// - [`VerifyingKey::with_context`](crate::VerifyingKey::with_context)
///
/// For more information, see [RFC8032 § 8.3](https://www.rfc-editor.org/rfc/rfc8032#section-8.3).
#[derive(Clone, Debug)]
pub struct Context<'k, 'v, K> {
    /// Key this context is being used with.
    key: &'k K,

    /// Context value: a bytestring no longer than 255 octets.
    value: &'v [u8],
}

impl<'k, 'v, K> Context<'k, 'v, K> {
    /// Maximum length of the context value in octets.
    pub const MAX_LENGTH: usize = 255;

    /// Create a new Ed25519ctx/Ed25519ph context.
    pub(crate) fn new(key: &'k K, value: &'v [u8]) -> Result<Self, SignatureError> {
        if value.len() <= Self::MAX_LENGTH {
            Ok(Self { key, value })
        } else {
            Err(SignatureError::from(InternalError::PrehashedContextLength))
        }
    }

    /// Borrow the key.
    pub fn key(&self) -> &'k K {
        self.key
    }

    /// Borrow the context string value.
    pub fn value(&self) -> &'v [u8] {
        self.value
    }
}

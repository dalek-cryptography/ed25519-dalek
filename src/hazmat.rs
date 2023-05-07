//! Low-level interfaces to ed25519 functions
//!
//! # ⚠️ Warning: Hazmat
//!
//! These primitives are easy-to-misuse low-level interfaces.
//!
//! If you are an end user / non-expert in cryptography, **do not use any of these functions**.
//! Failure to use them correctly can lead to catastrophic failures including **full private key
//! recovery.**

use crate::{InternalError, SignatureError};

use curve25519_dalek::Scalar;

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

// These are used in the functions that are made public when the hazmat feature is set
#[cfg(feature = "hazmat")]
use crate::{Signature, VerifyingKey};
#[cfg(feature = "hazmat")]
use curve25519_dalek::digest::{generic_array::typenum::U64, Digest};

/// Contains the secret scalar and domain separator used for generating signatures.
///
/// This is used internally for signing.
///
/// In the usual Ed25519 signing algorithm, `scalar` and `hash_prefix` are defined such that
/// `scalar || hash_prefix = H(sk)` where `sk` is the signing key and `H` is SHA-512.
/// **WARNING:** Deriving the values for these fields in any other way can lead to full key
/// recovery, as documented in [`raw_sign`] and [`raw_sign_prehashed`].
///
/// Instances of this secret are automatically overwritten with zeroes when they fall out of scope.
pub struct ExpandedSecretKey {
    /// The secret scalar used for signing
    pub scalar: Scalar,
    /// The domain separator used when hashing the message to generate the pseudorandom `r` value
    pub hash_prefix: [u8; 32],
}

#[cfg(feature = "zeroize")]
impl Drop for ExpandedSecretKey {
    fn drop(&mut self) {
        self.scalar.zeroize();
        self.hash_prefix.zeroize()
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for ExpandedSecretKey {}

// Some conversion methods for `ExpandedSecretKey`. The signing methods are defined in
// `signing.rs`, since we need them even when `not(feature = "hazmat")`
impl ExpandedSecretKey {
    /// Convert this `ExpandedSecretKey` into an array of 64 bytes.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes: [u8; 64] = [0u8; 64];

        bytes[..32].copy_from_slice(self.scalar.as_bytes());
        bytes[32..].copy_from_slice(&self.hash_prefix[..]);
        bytes
    }

    /// Construct an `ExpandedSecretKey` from a slice of bytes.
    ///
    /// # Returns
    ///
    /// A `Result` whose okay value is an EdDSA `ExpandedSecretKey` or whose error value is an
    /// `SignatureError` describing the error that occurred.
    pub fn from_bytes(bytes: &[u8]) -> Result<ExpandedSecretKey, SignatureError> {
        if bytes.len() != 64 {
            return Err(InternalError::BytesLength {
                name: "ExpandedSecretKey",
                length: 64,
            }
            .into());
        }
        let mut lower: [u8; 32] = [0u8; 32];
        let mut upper: [u8; 32] = [0u8; 32];

        lower.copy_from_slice(&bytes[00..32]);
        upper.copy_from_slice(&bytes[32..64]);

        Ok(ExpandedSecretKey {
            scalar: Scalar::from_bytes_mod_order(lower),
            hash_prefix: upper,
        })
    }
}

/// Compute an ordinary Ed25519 signature over the given message. `CtxDigest` is the digest used to
/// calculate the pseudorandomness needed for signing. This is SHA-512 in Ed25519.
///
/// # ⚠️  Unsafe
///
/// Do NOT use this function unless you absolutely must. Using the wrong values in
/// `ExpandedSecretKey` can leak your signing key. See
/// [here](https://github.com/MystenLabs/ed25519-unsafe-libs) for more details on this attack.
#[cfg(feature = "hazmat")]
pub fn raw_sign<CtxDigest>(
    esk: ExpandedSecretKey,
    message: &[u8],
    verifying_key: &VerifyingKey,
) -> Signature
where
    CtxDigest: Digest<OutputSize = U64>,
{
    esk.raw_sign::<CtxDigest>(message, verifying_key)
}

/// Compute a signature over the given prehashed message, the Ed25519ph algorithm defined in
/// [RFC8032 §5.1][rfc8032]. `MsgDigest` is the digest function used to hash the signed message.
/// `CtxDigest` is the digest function used to calculate the pseudorandomness needed for signing.
/// These are both SHA-512 in Ed25519.
///
/// # ⚠️  Unsafe
//
/// Do NOT use this function unless you absolutely must. Using the wrong values in
/// `ExpandedSecretKey` can leak your signing key. See
/// [here](https://github.com/MystenLabs/ed25519-unsafe-libs) for more details on this attack.
///
/// # Inputs
///
/// * `sk` is the [`ExpandedSecretKey`] being used for signing
/// * `prehashed_message` is an instantiated hash digest with 512-bits of
///   output which has had the message to be signed previously fed into its
///   state.
/// * `verifying_key` is a [`VerifyingKey`] which corresponds to this secret key.
/// * `context` is an optional context string, up to 255 bytes inclusive,
///   which may be used to provide additional domain separation.  If not
///   set, this will default to an empty string.
///
/// `scalar` and `hash_prefix` are usually selected such that `scalar || hash_prefix = H(sk)` where
/// `sk` is the signing key
///
/// # Returns
///
/// A `Result` whose `Ok` value is an Ed25519ph [`Signature`] on the
/// `prehashed_message` if the context was 255 bytes or less, otherwise
/// a `SignatureError`.
///
/// [rfc8032]: https://tools.ietf.org/html/rfc8032#section-5.1
#[cfg(all(feature = "hazmat", feature = "digest"))]
#[allow(non_snake_case)]
pub fn raw_sign_prehashed<'a, MsgDigest, CtxDigest>(
    esk: ExpandedSecretKey,
    prehashed_message: MsgDigest,
    verifying_key: &VerifyingKey,
    context: Option<&'a [u8]>,
) -> Result<Signature, SignatureError>
where
    MsgDigest: Digest<OutputSize = U64>,
    CtxDigest: Digest<OutputSize = U64>,
{
    esk.raw_sign_prehashed::<MsgDigest, CtxDigest>(prehashed_message, verifying_key, context)
}

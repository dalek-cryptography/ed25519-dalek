//! Low-level interfaces to ed25519 functions
//!
//! # ⚠️ Warning: Hazmat
//!
//! These primitives are easy-to-misuse low-level interfaces.
//!
//! If you are an end user / non-expert in cryptography, **do not use any of these functions**.
//! Failure to use them correctly can lead to catastrophic failures including **full private key
//! recovery.**

use crate::{
    signing::{private_raw_sign, private_raw_sign_prehashed},
    Signature, SignatureError, VerifyingKey,
};

use curve25519_dalek::{
    digest::{generic_array::typenum::U64, Digest},
    Scalar,
};

/// Computes an ordinary Ed25519 signature over the given message.
///
/// # ⚠️  Unsafe
///
/// Do NOT use this function unless you absolutely must. Misuse of this function can expose your
/// private key. See [here](https://github.com/MystenLabs/ed25519-unsafe-libs) for more details on
/// this attack.
///
/// # Inputs
///
/// * `scalar` is the secret scalar of the signing key
/// * `hash_prefix` is the domain separator that, along with the message itself, is used to
///   deterministically generate the `R` part of the signature.
///
/// `scalar` and `hash_prefix` are usually selected such that `scalar || hash_prefix = H(sk)` where
/// `sk` is the signing key
pub fn raw_sign(
    scalar: Scalar,
    hash_prefix: [u8; 32],
    message: &[u8],
    verifying_key: &VerifyingKey,
) -> Signature {
    private_raw_sign(scalar, hash_prefix, message, verifying_key)
}

/// Computes a signature over the given prehashed message, the Ed25519ph algorithm defined in
/// [RFC8032 §5.1][rfc8032].
///
/// # ⚠️  Unsafe
//
/// Do NOT use this function unless you absolutely must. Misuse of this function can expose your
/// private key. See [here](https://github.com/MystenLabs/ed25519-unsafe-libs) for more details on
/// this attack.
///
/// # Inputs
///
/// * `scalar` is the secret scalar of the signing key
/// * `hash_prefix` is the domain separator that, along with the prehashed message, is used to
///   deterministically generate the `R` part of the signature.
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
#[cfg(feature = "digest")]
#[allow(non_snake_case)]
pub fn raw_sign_prehashed<'a, D>(
    scalar: Scalar,
    hash_prefix: [u8; 32],
    prehashed_message: D,
    verifying_key: &VerifyingKey,
    context: Option<&'a [u8]>,
) -> Result<Signature, SignatureError>
where
    D: Digest<OutputSize = U64>,
{
    private_raw_sign_prehashed(
        scalar,
        hash_prefix,
        prehashed_message,
        verifying_key,
        context,
    )
}

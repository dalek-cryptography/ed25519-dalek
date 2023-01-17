// -*- mode: rust; -*-
//
// This file is part of ed25519-dalek.
// Copyright (c) 2017-2019 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! ed25519 public keys.

use core::convert::TryFrom;
use core::fmt::Debug;

use curve25519_dalek::digest::generic_array::typenum::U64;
use curve25519_dalek::digest::Digest;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

use ed25519::signature::Verifier;

pub use sha2::Sha512;

#[cfg(feature = "pkcs8")]
use ed25519::pkcs8::{self, DecodePublicKey};

#[cfg(feature = "serde")]
use serde::de::Error as SerdeError;
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
#[cfg(feature = "serde")]
use serde_bytes::{ByteBuf as SerdeByteBuf, Bytes as SerdeBytes};

use crate::constants::*;
use crate::errors::*;
use crate::signature::*;
use crate::signing::*;

/// An ed25519 public key.
// Invariant: VerifyingKey.1 is always the decompression of VerifyingKey.0
#[derive(Copy, Clone, Default, Eq, PartialEq)]
pub struct VerifyingKey(pub(crate) CompressedEdwardsY, pub(crate) EdwardsPoint);

impl Debug for VerifyingKey {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "VerifyingKey({:?}), {:?})", self.0, self.1)
    }
}

impl AsRef<[u8]> for VerifyingKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl From<&ExpandedSecretKey> for VerifyingKey {
    /// Derive this public key from its corresponding `ExpandedSecretKey`.
    fn from(expanded_secret_key: &ExpandedSecretKey) -> VerifyingKey {
        let mut bits: [u8; 32] = expanded_secret_key.key.to_bytes();
        VerifyingKey::mangle_scalar_bits_and_multiply_by_basepoint_to_produce_public_key(&mut bits)
    }
}

impl From<&SigningKey> for VerifyingKey {
    fn from(signing_key: &SigningKey) -> VerifyingKey {
        signing_key.verifying_key()
    }
}

impl VerifyingKey {
    /// Convert this public key to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.0.to_bytes()
    }

    /// View this public key as a byte array.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        &(self.0).0
    }

    /// Construct a `VerifyingKey` from a slice of bytes.
    ///
    /// # Warning
    ///
    /// The caller is responsible for ensuring that the bytes passed into this
    /// method actually represent a `curve25519_dalek::curve::CompressedEdwardsY`
    /// and that said compressed point is actually a point on the curve.
    ///
    /// # Example
    ///
    /// ```
    /// use ed25519_dalek::VerifyingKey;
    /// use ed25519_dalek::PUBLIC_KEY_LENGTH;
    /// use ed25519_dalek::SignatureError;
    ///
    /// # fn doctest() -> Result<VerifyingKey, SignatureError> {
    /// let public_key_bytes: [u8; PUBLIC_KEY_LENGTH] = [
    ///    215,  90, 152,   1, 130, 177,  10, 183, 213,  75, 254, 211, 201, 100,   7,  58,
    ///     14, 225, 114, 243, 218, 166,  35,  37, 175,   2,  26, 104, 247,   7,   81, 26];
    ///
    /// let public_key = VerifyingKey::from_bytes(&public_key_bytes)?;
    /// #
    /// # Ok(public_key)
    /// # }
    /// #
    /// # fn main() {
    /// #     doctest();
    /// # }
    /// ```
    ///
    /// # Returns
    ///
    /// A `Result` whose okay value is an EdDSA `VerifyingKey` or whose error value
    /// is an `SignatureError` describing the error that occurred.
    #[inline]
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LENGTH]) -> Result<VerifyingKey, SignatureError> {
        let compressed = CompressedEdwardsY(*bytes);
        let point = compressed
            .decompress()
            .ok_or(InternalError::PointDecompression)?;

        // Invariant: VerifyingKey.1 is always the decompression of VerifyingKey.0
        Ok(VerifyingKey(compressed, point))
    }

    /// Internal utility function for mangling the bits of a (formerly
    /// mathematically well-defined) "scalar" and multiplying it to produce a
    /// public key.
    fn mangle_scalar_bits_and_multiply_by_basepoint_to_produce_public_key(
        bits: &mut [u8; 32],
    ) -> VerifyingKey {
        bits[0] &= 248;
        bits[31] &= 127;
        bits[31] |= 64;

        let scalar = Scalar::from_bits(*bits);
        let point = EdwardsPoint::mul_base(&scalar);
        let compressed = point.compress();

        // Invariant: VerifyingKey.1 is always the decompression of VerifyingKey.0
        VerifyingKey(compressed, point)
    }

    // A helper function that computes H(R || A || M). If `context.is_some()`, this does the
    // prehashed variant of the computation using its contents.
    #[allow(non_snake_case)]
    fn compute_challenge(
        context: Option<&[u8]>,
        R: &CompressedEdwardsY,
        A: &CompressedEdwardsY,
        M: &[u8],
    ) -> Scalar {
        let mut h = Sha512::new();
        if let Some(c) = context {
            h.update(b"SigEd25519 no Ed25519 collisions");
            h.update([1]); // Ed25519ph
            h.update([c.len() as u8]);
            h.update(c);
        }
        h.update(R.as_bytes());
        h.update(A.as_bytes());
        h.update(M);

        Scalar::from_hash(h)
    }

    // Helper function for verification. Computes the _expected_ R component of the signature. The
    // caller compares this to the real R component.  If `context.is_some()`, this does the
    // prehashed variant of the computation using its contents.
    #[allow(non_snake_case)]
    fn recompute_r(
        &self,
        context: Option<&[u8]>,
        signature: &InternalSignature,
        M: &[u8],
    ) -> EdwardsPoint {
        let k = Self::compute_challenge(context, &signature.R, &self.0, M);
        let minus_A: EdwardsPoint = -self.1;
        // Recall the (non-batched) verification equation: -[k]A + [s]B = R
        EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &(minus_A), &signature.s)
    }

    /// Verify a `signature` on a `prehashed_message` using the Ed25519ph algorithm.
    ///
    /// # Inputs
    ///
    /// * `prehashed_message` is an instantiated hash digest with 512-bits of
    ///   output which has had the message to be signed previously fed into its
    ///   state.
    /// * `context` is an optional context string, up to 255 bytes inclusive,
    ///   which may be used to provide additional domain separation.  If not
    ///   set, this will default to an empty string.
    /// * `signature` is a purported Ed25519ph [`Signature`] on the `prehashed_message`.
    ///
    /// # Returns
    ///
    /// Returns `true` if the `signature` was a valid signature created by this
    /// `Keypair` on the `prehashed_message`.
    ///
    /// [rfc8032]: https://tools.ietf.org/html/rfc8032#section-5.1
    #[allow(non_snake_case)]
    pub fn verify_prehashed<D>(
        &self,
        prehashed_message: D,
        context: Option<&[u8]>,
        signature: &ed25519::Signature,
    ) -> Result<(), SignatureError>
    where
        D: Digest<OutputSize = U64>,
    {
        let signature = InternalSignature::try_from(signature)?;

        let ctx: &[u8] = context.unwrap_or(b"");
        debug_assert!(
            ctx.len() <= 255,
            "The context must not be longer than 255 octets."
        );

        let message = prehashed_message.finalize();
        let expected_R = self.recompute_r(Some(ctx), &signature, &message);

        if expected_R.compress() == signature.R {
            Ok(())
        } else {
            Err(InternalError::Verify.into())
        }
    }

    /// Strictly verify a signature on a message with this keypair's public key.
    ///
    /// # On The (Multiple) Sources of Malleability in Ed25519 Signatures
    ///
    /// This version of verification is technically non-RFC8032 compliant.  The
    /// following explains why.
    ///
    /// 1. Scalar Malleability
    ///
    /// The authors of the RFC explicitly stated that verification of an ed25519
    /// signature must fail if the scalar `s` is not properly reduced mod \ell:
    ///
    /// > To verify a signature on a message M using public key A, with F
    /// > being 0 for Ed25519ctx, 1 for Ed25519ph, and if Ed25519ctx or
    /// > Ed25519ph is being used, C being the context, first split the
    /// > signature into two 32-octet halves.  Decode the first half as a
    /// > point R, and the second half as an integer S, in the range
    /// > 0 <= s < L.  Decode the public key A as point A'.  If any of the
    /// > decodings fail (including S being out of range), the signature is
    /// > invalid.)
    ///
    /// All `verify_*()` functions within ed25519-dalek perform this check.
    ///
    /// 2. Point malleability
    ///
    /// The authors of the RFC added in a malleability check to step #3 in
    /// §5.1.7, for small torsion components in the `R` value of the signature,
    /// *which is not strictly required*, as they state:
    ///
    /// > Check the group equation \[8\]\[S\]B = \[8\]R + \[8\]\[k\]A'.  It's
    /// > sufficient, but not required, to instead check \[S\]B = R + \[k\]A'.
    ///
    /// # History of Malleability Checks
    ///
    /// As originally defined (cf. the "Malleability" section in the README of
    /// this repo), ed25519 signatures didn't consider *any* form of
    /// malleability to be an issue.  Later the scalar malleability was
    /// considered important.  Still later, particularly with interests in
    /// cryptocurrency design and in unique identities (e.g. for Signal users,
    /// Tor onion services, etc.), the group element malleability became a
    /// concern.
    ///
    /// However, libraries had already been created to conform to the original
    /// definition.  One well-used library in particular even implemented the
    /// group element malleability check, *but only for batch verification*!
    /// Which meant that even using the same library, a single signature could
    /// verify fine individually, but suddenly, when verifying it with a bunch
    /// of other signatures, the whole batch would fail!
    ///
    /// # "Strict" Verification
    ///
    /// This method performs *both* of the above signature malleability checks.
    ///
    /// It must be done as a separate method because one doesn't simply get to
    /// change the definition of a cryptographic primitive ten years
    /// after-the-fact with zero consideration for backwards compatibility in
    /// hardware and protocols which have it already have the older definition
    /// baked in.
    ///
    /// # Return
    ///
    /// Returns `Ok(())` if the signature is valid, and `Err` otherwise.
    #[allow(non_snake_case)]
    pub fn verify_strict(
        &self,
        message: &[u8],
        signature: &ed25519::Signature,
    ) -> Result<(), SignatureError> {
        let signature = InternalSignature::try_from(signature)?;

        let signature_R = signature
            .R
            .decompress()
            .ok_or_else(|| SignatureError::from(InternalError::Verify))?;

        // Logical OR is fine here as we're not trying to be constant time.
        if signature_R.is_small_order() || self.1.is_small_order() {
            return Err(InternalError::Verify.into());
        }

        let expected_R = self.recompute_r(None, &signature, message);
        if expected_R == signature_R {
            Ok(())
        } else {
            Err(InternalError::Verify.into())
        }
    }

    /// Verify a `signature` on a `prehashed_message` using the Ed25519ph algorithm,
    /// using strict signture checking as defined by [`Self::verify_strict`].
    ///
    /// # Inputs
    ///
    /// * `prehashed_message` is an instantiated hash digest with 512-bits of
    ///   output which has had the message to be signed previously fed into its
    ///   state.
    /// * `context` is an optional context string, up to 255 bytes inclusive,
    ///   which may be used to provide additional domain separation.  If not
    ///   set, this will default to an empty string.
    /// * `signature` is a purported Ed25519ph [`Signature`] on the `prehashed_message`.
    ///
    /// # Returns
    ///
    /// Returns `true` if the `signature` was a valid signature created by this
    /// `Keypair` on the `prehashed_message`.
    #[allow(non_snake_case)]
    pub fn verify_prehashed_strict<D>(
        &self,
        prehashed_message: D,
        context: Option<&[u8]>,
        signature: &ed25519::Signature,
    ) -> Result<(), SignatureError>
    where
        D: Digest<OutputSize = U64>,
    {
        let signature = InternalSignature::try_from(signature)?;

        let ctx: &[u8] = context.unwrap_or(b"");
        debug_assert!(
            ctx.len() <= 255,
            "The context must not be longer than 255 octets."
        );

        let signature_R = signature
            .R
            .decompress()
            .ok_or_else(|| SignatureError::from(InternalError::Verify))?;

        // Logical OR is fine here as we're not trying to be constant time.
        if signature_R.is_small_order() || self.1.is_small_order() {
            return Err(InternalError::Verify.into());
        }

        let message = prehashed_message.finalize();
        let expected_R = self.recompute_r(Some(ctx), &signature, &message);

        if expected_R == signature_R {
            Ok(())
        } else {
            Err(InternalError::Verify.into())
        }
    }
}

impl Verifier<ed25519::Signature> for VerifyingKey {
    /// Verify a signature on a message with this keypair's public key.
    ///
    /// # Return
    ///
    /// Returns `Ok(())` if the signature is valid, and `Err` otherwise.
    #[allow(non_snake_case)]
    fn verify(&self, message: &[u8], signature: &ed25519::Signature) -> Result<(), SignatureError> {
        let signature = InternalSignature::try_from(signature)?;

        let expected_R = self.recompute_r(None, &signature, message);
        if expected_R.compress() == signature.R {
            Ok(())
        } else {
            Err(InternalError::Verify.into())
        }
    }
}

impl TryFrom<&[u8]> for VerifyingKey {
    type Error = SignatureError;

    #[inline]
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let bytes = bytes.try_into().map_err(|_| InternalError::BytesLength {
            name: "VerifyingKey",
            length: PUBLIC_KEY_LENGTH,
        })?;
        Self::from_bytes(bytes)
    }
}

#[cfg(feature = "pkcs8")]
impl DecodePublicKey for VerifyingKey {}

#[cfg(all(feature = "alloc", feature = "pkcs8"))]
impl pkcs8::EncodePublicKey for VerifyingKey {
    fn to_public_key_der(&self) -> pkcs8::spki::Result<pkcs8::Document> {
        pkcs8::PublicKeyBytes::from(self).to_public_key_der()
    }
}

#[cfg(feature = "pkcs8")]
impl TryFrom<pkcs8::PublicKeyBytes> for VerifyingKey {
    type Error = pkcs8::spki::Error;

    fn try_from(pkcs8_key: pkcs8::PublicKeyBytes) -> pkcs8::spki::Result<Self> {
        VerifyingKey::try_from(&pkcs8_key)
    }
}

#[cfg(feature = "pkcs8")]
impl TryFrom<&pkcs8::PublicKeyBytes> for VerifyingKey {
    type Error = pkcs8::spki::Error;

    fn try_from(pkcs8_key: &pkcs8::PublicKeyBytes) -> pkcs8::spki::Result<Self> {
        VerifyingKey::from_bytes(pkcs8_key.as_ref()).map_err(|_| pkcs8::spki::Error::KeyMalformed)
    }
}

#[cfg(feature = "pkcs8")]
impl From<VerifyingKey> for pkcs8::PublicKeyBytes {
    fn from(verifying_key: VerifyingKey) -> pkcs8::PublicKeyBytes {
        pkcs8::PublicKeyBytes::from(&verifying_key)
    }
}

#[cfg(feature = "pkcs8")]
impl From<&VerifyingKey> for pkcs8::PublicKeyBytes {
    fn from(verifying_key: &VerifyingKey) -> pkcs8::PublicKeyBytes {
        pkcs8::PublicKeyBytes(verifying_key.to_bytes())
    }
}

#[cfg(feature = "pkcs8")]
impl TryFrom<pkcs8::spki::SubjectPublicKeyInfo<'_>> for VerifyingKey {
    type Error = pkcs8::spki::Error;

    fn try_from(public_key: pkcs8::spki::SubjectPublicKeyInfo<'_>) -> pkcs8::spki::Result<Self> {
        pkcs8::PublicKeyBytes::try_from(public_key)?.try_into()
    }
}

#[cfg(feature = "serde")]
impl Serialize for VerifyingKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        SerdeBytes::new(self.as_bytes()).serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'d> Deserialize<'d> for VerifyingKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        let bytes = <SerdeByteBuf>::deserialize(deserializer)?;
        VerifyingKey::try_from(bytes.as_ref()).map_err(SerdeError::custom)
    }
}

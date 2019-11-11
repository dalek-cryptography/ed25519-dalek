// -*- mode: rust; -*-
//
// This file is part of ed25519-dalek.
// Copyright (c) 2017-2019 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! An ed25519 signature.

#![allow(non_snake_case)]
#![allow(absolute_paths_not_starting_with_crate)]

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;

use crate::constants::*;

// Re-export the `ed25519` crate's Signature type
pub use ed25519_crate::{Signature, signature::Signature as SignatureTrait};

/// Extension trait for the `Signature` type providing access to the
/// `R` and `s` components of the signature.
pub(crate) trait SignatureExt {
    /// Create a signature from its `R` and `s` values.
    fn from_R_and_s(R: CompressedEdwardsY, s: Scalar) -> Self;

    /// `R` is an `EdwardsPoint`, formed by using an hash function with
    /// 512-bits output to produce the digest of:
    ///
    /// - the nonce half of the `ExpandedSecretKey`, and
    /// - the message to be signed.
    ///
    /// This digest is then interpreted as a `Scalar` and reduced into an
    /// element in ℤ/lℤ.  The scalar is then multiplied by the distinguished
    /// basepoint to produce `R`, and `EdwardsPoint`.
    fn R(&self) -> CompressedEdwardsY;

    /// `s` is a `Scalar`, formed by using an hash function with 512-bits output
    /// to produce the digest of:
    ///
    /// - the `r` portion of this `Signature`,
    /// - the `PublicKey` which should be used to verify this `Signature`, and
    /// - the message to be signed.
    ///
    /// This digest is then interpreted as a `Scalar` and reduced into an
    /// element in ℤ/lℤ.
    fn s(&self) -> Scalar;
}

impl SignatureExt for Signature {
    fn from_R_and_s(R: CompressedEdwardsY, s: Scalar) -> Signature {
        let mut signature_bytes: [u8; SIGNATURE_LENGTH] = [0u8; SIGNATURE_LENGTH];
        signature_bytes[..32].copy_from_slice(&R.as_bytes()[..]);
        signature_bytes[32..].copy_from_slice(&s.as_bytes()[..]);
        Signature::from_bytes(&signature_bytes[..]).unwrap()
    }

    fn R(&self) -> CompressedEdwardsY {
        let mut lower: [u8; 32] = [0u8; 32];
        lower.copy_from_slice(&self.as_ref()[..32]);
        CompressedEdwardsY(lower)
    }

    fn s(&self) -> Scalar {
        let mut upper: [u8; 32] = [0u8; 32];
        upper.copy_from_slice(&self.as_ref()[32..]);
        debug_assert_eq!(upper[31] & 224, 0);
        Scalar::from_bits(upper)
    }
}

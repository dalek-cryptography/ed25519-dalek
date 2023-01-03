// -*- mode: rust; -*-
//
// This file is part of ed25519-dalek.
// Copyright (c) 2017-2019 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! Batch signature verification.

use alloc::vec::Vec;

use core::convert::TryFrom;
use core::iter::once;

use curve25519_dalek::constants;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use curve25519_dalek::traits::VartimeMultiscalarMul;

pub use curve25519_dalek::digest::Digest;

use merlin::Transcript;

use rand::Rng;

use sha2::Sha512;

use crate::errors::InternalError;
use crate::errors::SignatureError;
use crate::signature::InternalSignature;
use crate::VerifyingKey;

trait BatchTranscript {
    fn append_scalars(&mut self, scalars: &Vec<Scalar>);
    fn append_message_lengths(&mut self, message_lengths: &Vec<usize>);
}

impl BatchTranscript for Transcript {
    /// Append some `scalars` to this batch verification sigma protocol transcript.
    ///
    /// For ed25519 batch verification, we include the following as scalars:
    ///
    /// * All of the computed `H(R||A||M)`s to the protocol transcript, and
    /// * All of the `s` components of each signature.
    ///
    /// Each is also prefixed with their index in the vector.
    fn append_scalars(&mut self, scalars: &Vec<Scalar>) {
        for (i, scalar) in scalars.iter().enumerate() {
            self.append_u64(b"", i as u64);
            self.append_message(b"hram", scalar.as_bytes());
        }
    }

    /// Append the lengths of the messages into the transcript.
    ///
    /// This is done out of an (potential over-)abundance of caution, to guard against the unlikely
    /// event of collisions.  However, a nicer way to do this would be to append the message length
    /// before the message, but this is messy w.r.t. the calculations of the `H(R||A||M)`s above.
    fn append_message_lengths(&mut self, message_lengths: &Vec<usize>) {
        for (i, len) in message_lengths.iter().enumerate() {
            self.append_u64(b"", i as u64);
            self.append_u64(b"mlen", *len as u64);
        }
    }
}

/// An implementation of `rand_core::RngCore` which does nothing, to provide purely deterministic
/// transcript-based nonces, rather than synthetically random nonces.
struct ZeroRng;

impl rand_core::RngCore for ZeroRng {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    /// A no-op function which leaves the destination bytes for randomness unchanged.
    ///
    /// In this case, the internal merlin code is initialising the destination
    /// by doing `[0u8; …]`, which means that when we call
    /// `merlin::TranscriptRngBuilder.finalize()`, rather than rekeying the
    /// STROBE state based on external randomness, we're doing an
    /// `ENC_{state}(00000000000000000000000000000000)` operation, which is
    /// identical to the STROBE `MAC` operation.
    fn fill_bytes(&mut self, _dest: &mut [u8]) {}

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for ZeroRng {}

/// Verify a batch of `signatures` on `messages` with their respective `verifying_keys`.
///
/// # Inputs
///
/// * `messages` is a slice of byte slices, one per signed message.
/// * `signatures` is a slice of `Signature`s.
/// * `verifying_keys` is a slice of `VerifyingKey`s.
///
/// # Returns
///
/// * A `Result` whose `Ok` value is an emtpy tuple and whose `Err` value is a
///   `SignatureError` containing a description of the internal error which
///   occured.
///
/// ## On Synthetic Nonces
///
/// This library defaults to using what is called "synthetic" nonces, which
/// means that a mixture of deterministic (per any unique set of inputs to this
/// function) data and system randomness is used to seed the CSPRNG for nonce
/// generation.  For more of the background theory on why many cryptographers
/// currently believe this to be superior to either purely deterministic
/// generation or purely relying on the system's randomness, see [this section
/// of the Merlin design](https://merlin.cool/transcript/rng.html) by Henry de
/// Valence, isis lovecruft, and Oleg Andreev, as well as Trevor Perrin's
/// [designs for generalised
/// EdDSA](https://moderncrypto.org/mail-archive/curves/2017/000925.html).
///
/// ## On Deterministic Nonces
///
/// The nonces for batch signature verification are derived purely from the inputs to this function
/// themselves.
///
/// In any sigma protocol it is wise to include as much context pertaining
/// to the public state in the protocol as possible, to avoid malleability
/// attacks where an adversary alters publics in an algebraic manner that
/// manages to satisfy the equations for the protocol in question.
///
/// For ed25519 batch verification (both with synthetic and deterministic nonce
/// generation), we include the following as scalars in the protocol transcript:
///
/// * All of the computed `H(R||A||M)`s to the protocol transcript, and
/// * All of the `s` components of each signature.
///
/// Each is also prefixed with their index in the vector.
///
/// The former, while not quite as elegant as adding the `R`s, `A`s, and
/// `M`s separately, saves us a bit of context hashing since the
/// `H(R||A||M)`s need to be computed for the verification equation anyway.
///
/// The latter prevents a malleability attack wherein an adversary, without access
/// to the signing key(s), can take any valid signature, `(s,R)`, and swap
/// `s` with `s' = -z1`.  This doesn't constitute a signature forgery, merely
/// a vulnerability, as the resulting signature will not pass single
/// signature verification.  (Thanks to Github users @real_or_random and
/// @jonasnick for pointing out this malleability issue.)
///
/// # Examples
///
/// ```
/// use ed25519_dalek::{
///     verify_batch, SigningKey, VerifyingKey, Signer, Signature,
/// };
/// use rand::rngs::OsRng;
///
/// # fn main() {
/// let mut csprng = OsRng;
/// let signing_keys: Vec<_> = (0..64).map(|_| SigningKey::generate(&mut csprng)).collect();
/// let msg: &[u8] = b"They're good dogs Brant";
/// let messages: Vec<_> = (0..64).map(|_| msg).collect();
/// let signatures:  Vec<_> = signing_keys.iter().map(|key| key.sign(&msg)).collect();
/// let verifying_keys: Vec<_> = signing_keys.iter().map(|key| key.verifying_key()).collect();
///
/// let result = verify_batch(&messages, &signatures, &verifying_keys);
/// assert!(result.is_ok());
/// # }
/// ```
#[allow(non_snake_case)]
pub fn verify_batch(
    messages: &[&[u8]],
    signatures: &[ed25519::Signature],
    verifying_keys: &[VerifyingKey],
) -> Result<(), SignatureError> {
    // Return an Error if any of the vectors were not the same size as the others.
    if signatures.len() != messages.len()
        || signatures.len() != verifying_keys.len()
        || verifying_keys.len() != messages.len()
    {
        return Err(InternalError::ArrayLength {
            name_a: "signatures",
            length_a: signatures.len(),
            name_b: "messages",
            length_b: messages.len(),
            name_c: "verifying_keys",
            length_c: verifying_keys.len(),
        }
        .into());
    }

    // Convert all signatures to `InternalSignature`
    let signatures = signatures
        .iter()
        .map(InternalSignature::try_from)
        .collect::<Result<Vec<_>, _>>()?;

    // Compute H(R || A || M) for each (signature, public_key, message) triplet
    let hrams: Vec<Scalar> = (0..signatures.len())
        .map(|i| {
            let mut h: Sha512 = Sha512::default();
            h.update(signatures[i].R.as_bytes());
            h.update(verifying_keys[i].as_bytes());
            h.update(&messages[i]);
            Scalar::from_hash(h)
        })
        .collect();

    // Collect the message lengths and the scalar portions of the signatures, and add them into the
    // transcript.
    let message_lengths: Vec<usize> = messages.iter().map(|i| i.len()).collect();
    let scalars: Vec<Scalar> = signatures.iter().map(|i| i.s).collect();

    // Build a PRNG based on a transcript of the H(R || A || M)s seen thus far. This provides
    // synthethic randomness in the default configuration, and purely deterministic in the case of
    // compiling with the "batch_deterministic" feature.
    let mut transcript: Transcript = Transcript::new(b"ed25519 batch verification");

    transcript.append_scalars(&hrams);
    transcript.append_message_lengths(&message_lengths);
    transcript.append_scalars(&scalars);

    let mut rng = transcript.build_rng().finalize(&mut ZeroRng);

    // Select a random 128-bit scalar for each signature.
    let zs: Vec<Scalar> = signatures
        .iter()
        .map(|_| Scalar::from(rng.gen::<u128>()))
        .collect();

    // Compute the basepoint coefficient, ∑ s[i]z[i] (mod l)
    let B_coefficient: Scalar = signatures
        .iter()
        .map(|sig| sig.s)
        .zip(zs.iter())
        .map(|(s, z)| z * s)
        .sum();

    // Multiply each H(R || A || M) by the random value
    let zhrams = hrams.iter().zip(zs.iter()).map(|(hram, z)| hram * z);

    let Rs = signatures.iter().map(|sig| sig.R.decompress());
    let As = verifying_keys.iter().map(|pk| Some(pk.1));
    let B = once(Some(constants::ED25519_BASEPOINT_POINT));

    // Compute (-∑ z[i]s[i] (mod l)) B + ∑ z[i]R[i] + ∑ (z[i]H(R||A||M)[i] (mod l)) A[i] = 0
    let id = EdwardsPoint::optional_multiscalar_mul(
        once(-B_coefficient).chain(zs.iter().cloned()).chain(zhrams),
        B.chain(Rs).chain(As),
    )
    .ok_or(InternalError::Verify)?;

    if id.is_identity() {
        Ok(())
    } else {
        Err(InternalError::Verify.into())
    }
}

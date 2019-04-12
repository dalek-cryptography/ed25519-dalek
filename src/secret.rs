// -*- mode: rust; -*-
//
// This file is part of ed25519-dalek.
// Copyright (c) 2017-2019 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! ed25519 secret key types.

use core::fmt::Debug;

use clear_on_drop::clear::Clear;

use curve25519_dalek::constants;
use curve25519_dalek::digest::generic_array::typenum::U64;
use curve25519_dalek::digest::Digest;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;

use rand::CryptoRng;
use rand::Rng;

use sha2::Sha512;

#[cfg(feature = "serde")]
use serde::de::Error as SerdeError;
#[cfg(feature = "serde")]
use serde::de::Visitor;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde::{Deserializer, Serializer};

use crate::constants::*;
use crate::errors::*;
use crate::public::*;
use crate::signature::*;

/// An EdDSA secret key.
#[derive(Default)] // we derive Default in order to use the clear() method in Drop
pub struct SecretKey(pub(crate) [u8; SECRET_KEY_LENGTH]);

impl Debug for SecretKey {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "SecretKey: {:?}", &self.0[..])
    }
}

/// Overwrite secret key material with null bytes when it goes out of scope.
impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.clear();
    }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl SecretKey {
    /// Convert this secret key to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.0
    }

    /// View this secret key as a byte array.
    #[inline]
    pub fn as_bytes<'a>(&'a self) -> &'a [u8; SECRET_KEY_LENGTH] {
        &self.0
    }

    /// Construct a `SecretKey` from a slice of bytes.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate ed25519_dalek;
    /// #
    /// use ed25519_dalek::SecretKey;
    /// use ed25519_dalek::SECRET_KEY_LENGTH;
    /// use ed25519_dalek::SignatureError;
    ///
    /// # fn doctest() -> Result<SecretKey, SignatureError> {
    /// let secret_key_bytes: [u8; SECRET_KEY_LENGTH] = [
    ///    157, 097, 177, 157, 239, 253, 090, 096,
    ///    186, 132, 074, 244, 146, 236, 044, 196,
    ///    068, 073, 197, 105, 123, 050, 105, 025,
    ///    112, 059, 172, 003, 028, 174, 127, 096, ];
    ///
    /// let secret_key: SecretKey = SecretKey::from_bytes(&secret_key_bytes)?;
    /// #
    /// # Ok(secret_key)
    /// # }
    /// #
    /// # fn main() {
    /// #     let result = doctest();
    /// #     assert!(result.is_ok());
    /// # }
    /// ```
    ///
    /// # Returns
    ///
    /// A `Result` whose okay value is an EdDSA `SecretKey` or whose error value
    /// is an `SignatureError` wrapping the internal error that occurred.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey, SignatureError> {
        if bytes.len() != SECRET_KEY_LENGTH {
            return Err(SignatureError(InternalError::BytesLengthError {
                name: "SecretKey",
                length: SECRET_KEY_LENGTH,
            }));
        }
        let mut bits: [u8; 32] = [0u8; 32];
        bits.copy_from_slice(&bytes[..32]);

        Ok(SecretKey(bits))
    }

    /// Generate a `SecretKey` from a `csprng`.
    ///
    /// # Example
    ///
    /// ```
    /// extern crate rand;
    /// extern crate sha2;
    /// extern crate ed25519_dalek;
    ///
    /// # #[cfg(feature = "std")]
    /// # fn main() {
    /// #
    /// use rand::Rng;
    /// use rand::rngs::OsRng;
    /// use sha2::Sha512;
    /// use ed25519_dalek::PublicKey;
    /// use ed25519_dalek::SecretKey;
    /// use ed25519_dalek::Signature;
    ///
    /// let mut csprng: OsRng = OsRng::new().unwrap();
    /// let secret_key: SecretKey = SecretKey::generate(&mut csprng);
    /// # }
    /// #
    /// # #[cfg(not(feature = "std"))]
    /// # fn main() { }
    /// ```
    ///
    /// Afterwards, you can generate the corresponding public:
    ///
    /// ```
    /// # extern crate rand;
    /// # extern crate ed25519_dalek;
    /// #
    /// # fn main() {
    /// #
    /// # use rand::Rng;
    /// # use rand::thread_rng;
    /// # use ed25519_dalek::PublicKey;
    /// # use ed25519_dalek::SecretKey;
    /// # use ed25519_dalek::Signature;
    /// #
    /// # let mut csprng = thread_rng();
    /// # let secret_key: SecretKey = SecretKey::generate(&mut csprng);
    ///
    /// let public_key: PublicKey = (&secret_key).into();
    /// # }
    /// ```
    ///
    /// # Input
    ///
    /// A CSPRNG with a `fill_bytes()` method, e.g. `rand::OsRng`
    pub fn generate<T>(csprng: &mut T) -> SecretKey
    where
        T: CryptoRng + Rng,
    {
        let mut sk: SecretKey = SecretKey([0u8; 32]);

        csprng.fill_bytes(&mut sk.0);

        sk
    }
}

#[cfg(feature = "serde")]
impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_bytes())
    }
}

#[cfg(feature = "serde")]
impl<'d> Deserialize<'d> for SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        struct SecretKeyVisitor;

        impl<'d> Visitor<'d> for SecretKeyVisitor {
            type Value = SecretKey;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                formatter.write_str("An ed25519 secret key as 32 bytes, as specified in RFC8032.")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<SecretKey, E>
            where
                E: SerdeError,
            {
                SecretKey::from_bytes(bytes).or(Err(SerdeError::invalid_length(bytes.len(), &self)))
            }
        }
        deserializer.deserialize_bytes(SecretKeyVisitor)
    }
}

/// An "expanded" secret key.
///
/// This is produced by using an hash function with 512-bits output to digest a
/// `SecretKey`.  The output digest is then split in half, the lower half being
/// the actual `key` used to sign messages, after twiddling with some bits.¹ The
/// upper half is used a sort of half-baked, ill-designed² pseudo-domain-separation
/// "nonce"-like thing, which is used during signature production by
/// concatenating it with the message to be signed before the message is hashed.
//
// ¹ This results in a slight bias towards non-uniformity at one spectrum of
// the range of valid keys.  Oh well: not my idea; not my problem.
//
// ² It is the author's view (specifically, isis agora lovecruft, in the event
// you'd like to complain about me, again) that this is "ill-designed" because
// this doesn't actually provide true hash domain separation, in that in many
// real-world applications a user wishes to have one key which is used in
// several contexts (such as within tor, which does does domain separation
// manually by pre-concatenating static strings to messages to achieve more
// robust domain separation).  In other real-world applications, such as
// bitcoind, a user might wish to have one master keypair from which others are
// derived (à la BIP32) and different domain separators between keys derived at
// different levels (and similarly for tree-based key derivation constructions,
// such as hash-based signatures).  Leaving the domain separation to
// application designers, who thus far have produced incompatible,
// slightly-differing, ad hoc domain separation (at least those application
// designers who knew enough cryptographic theory to do so!), is therefore a
// bad design choice on the part of the cryptographer designing primitives
// which should be simple and as foolproof as possible to use for
// non-cryptographers.  Further, later in the ed25519 signature scheme, as
// specified in RFC8032, the public key is added into *another* hash digest
// (along with the message, again); it is unclear to this author why there's
// not only one but two poorly-thought-out attempts at domain separation in the
// same signature scheme, and which both fail in exactly the same way.  For a
// better-designed, Schnorr-based signature scheme, see Trevor Perrin's work on
// "generalised EdDSA" and "VXEdDSA".
#[derive(Default)] // we derive Default in order to use the clear() method in Drop
pub struct ExpandedSecretKey {
    pub(crate) key: Scalar,
    pub(crate) nonce: [u8; 32],
}

/// Overwrite secret key material with null bytes when it goes out of scope.
impl Drop for ExpandedSecretKey {
    fn drop(&mut self) {
        self.key.clear();
        self.nonce.clear();
    }
}

impl<'a> From<&'a SecretKey> for ExpandedSecretKey {
    /// Construct an `ExpandedSecretKey` from a `SecretKey`.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate rand;
    /// # extern crate sha2;
    /// # extern crate ed25519_dalek;
    /// #
    /// # fn main() {
    /// #
    /// use rand::Rng;
    /// use rand::thread_rng;
    /// use sha2::Sha512;
    /// use ed25519_dalek::{SecretKey, ExpandedSecretKey};
    ///
    /// let mut csprng = thread_rng();
    /// let secret_key: SecretKey = SecretKey::generate(&mut csprng);
    /// let expanded_secret_key: ExpandedSecretKey = ExpandedSecretKey::from(&secret_key);
    /// # }
    /// ```
    fn from(secret_key: &'a SecretKey) -> ExpandedSecretKey {
        let mut h: Sha512 = Sha512::default();
        let mut hash:  [u8; 64] = [0u8; 64];
        let mut lower: [u8; 32] = [0u8; 32];
        let mut upper: [u8; 32] = [0u8; 32];

        h.input(secret_key.as_bytes());
        hash.copy_from_slice(h.result().as_slice());

        lower.copy_from_slice(&hash[00..32]);
        upper.copy_from_slice(&hash[32..64]);

        lower[0]  &= 248;
        lower[31] &=  63;
        lower[31] |=  64;

        ExpandedSecretKey{ key: Scalar::from_bits(lower), nonce: upper, }
    }
}

impl ExpandedSecretKey {
    /// Convert this `ExpandedSecretKey` into an array of 64 bytes.
    ///
    /// # Returns
    ///
    /// An array of 64 bytes.  The first 32 bytes represent the "expanded"
    /// secret key, and the last 32 bytes represent the "domain-separation"
    /// "nonce".
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate rand;
    /// # extern crate sha2;
    /// # extern crate ed25519_dalek;
    /// #
    /// # #[cfg(all(feature = "sha2", feature = "std"))]
    /// # fn main() {
    /// #
    /// use rand::Rng;
    /// use rand::rngs::OsRng;
    /// use sha2::Sha512;
    /// use ed25519_dalek::{SecretKey, ExpandedSecretKey};
    ///
    /// let mut csprng: OsRng = OsRng::new().unwrap();
    /// let secret_key: SecretKey = SecretKey::generate(&mut csprng);
    /// let expanded_secret_key: ExpandedSecretKey = ExpandedSecretKey::from(&secret_key);
    /// let expanded_secret_key_bytes: [u8; 64] = expanded_secret_key.to_bytes();
    ///
    /// assert!(&expanded_secret_key_bytes[..] != &[0u8; 64][..]);
    /// # }
    /// #
    /// # #[cfg(any(not(feature = "sha2"), not(feature = "std")))]
    /// # fn main() { }
    /// ```
    #[inline]
    pub fn to_bytes(&self) -> [u8; EXPANDED_SECRET_KEY_LENGTH] {
        let mut bytes: [u8; 64] = [0u8; 64];

        bytes[..32].copy_from_slice(self.key.as_bytes());
        bytes[32..].copy_from_slice(&self.nonce[..]);
        bytes
    }

    /// Construct an `ExpandedSecretKey` from a slice of bytes.
    ///
    /// # Returns
    ///
    /// A `Result` whose okay value is an EdDSA `ExpandedSecretKey` or whose
    /// error value is an `SignatureError` describing the error that occurred.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate rand;
    /// # extern crate sha2;
    /// # extern crate ed25519_dalek;
    /// #
    /// # use ed25519_dalek::{ExpandedSecretKey, SignatureError};
    /// #
    /// # #[cfg(all(feature = "sha2", feature = "std"))]
    /// # fn do_test() -> Result<ExpandedSecretKey, SignatureError> {
    /// #
    /// use rand::Rng;
    /// use rand::rngs::OsRng;
    /// use ed25519_dalek::{SecretKey, ExpandedSecretKey};
    /// use ed25519_dalek::SignatureError;
    ///
    /// let mut csprng: OsRng = OsRng::new().unwrap();
    /// let secret_key: SecretKey = SecretKey::generate(&mut csprng);
    /// let expanded_secret_key: ExpandedSecretKey = ExpandedSecretKey::from(&secret_key);
    /// let bytes: [u8; 64] = expanded_secret_key.to_bytes();
    /// let expanded_secret_key_again = ExpandedSecretKey::from_bytes(&bytes)?;
    /// #
    /// # Ok(expanded_secret_key_again)
    /// # }
    /// #
    /// # #[cfg(all(feature = "sha2", feature = "std"))]
    /// # fn main() {
    /// #     let result = do_test();
    /// #     assert!(result.is_ok());
    /// # }
    /// #
    /// # #[cfg(any(not(feature = "sha2"), not(feature = "std")))]
    /// # fn main() { }
    /// ```
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<ExpandedSecretKey, SignatureError> {
        if bytes.len() != EXPANDED_SECRET_KEY_LENGTH {
            return Err(SignatureError(InternalError::BytesLengthError {
                name: "ExpandedSecretKey",
                length: EXPANDED_SECRET_KEY_LENGTH,
            }));
        }
        let mut lower: [u8; 32] = [0u8; 32];
        let mut upper: [u8; 32] = [0u8; 32];

        lower.copy_from_slice(&bytes[00..32]);
        upper.copy_from_slice(&bytes[32..64]);

        Ok(ExpandedSecretKey {
            key: Scalar::from_bits(lower),
            nonce: upper,
        })
    }

    /// From `SecretKey` using custom `Digest`
    pub fn from_secret_with_digest<D>(secret_key: &'_ SecretKey) -> ExpandedSecretKey
    where
        D: Digest<OutputSize = U64> + Digest + Default,
    {
        let mut h: D = D::default();
        let mut hash: [u8; 64] = [0u8; 64];
        let mut lower: [u8; 32] = [0u8; 32];
        let mut upper: [u8; 32] = [0u8; 32];

        h.input(secret_key.as_bytes());
        hash.copy_from_slice(h.result().as_slice());

        lower.copy_from_slice(&hash[00..32]);
        upper.copy_from_slice(&hash[32..64]);

        lower[0] &= 248;
        lower[31] &= 63;
        lower[31] |= 64;

        ExpandedSecretKey {
            key: Scalar::from_bits(lower),
            nonce: upper,
        }
    }

    /// Sign a message with this `ExpandedSecretKey`.
    #[allow(non_snake_case)]
    pub fn sign(&self, message: &[u8], public_key: &PublicKey) -> Signature {
        self.sign_with_digest::<Sha512>(message, public_key)
    }

    /// Sign a message with this `ExpandedSecretKey` using custom
    /// digest algorithm.
    #[allow(non_snake_case)]
    pub fn sign_with_digest<D>(&self, message: &[u8], public_key: &PublicKey) -> Signature
    where
        D: Digest<OutputSize = U64> + Digest + Default
    {
        let mut h: D = D::new();
        let R: CompressedEdwardsY;
        let r: Scalar;
        let s: Scalar;
        let k: Scalar;

        h.input(&self.nonce);
        h.input(&message);

        r = Scalar::from_hash(h);
        R = (&r * &constants::ED25519_BASEPOINT_TABLE).compress();

        h = D::new();
        h.input(R.as_bytes());
        h.input(public_key.as_bytes());
        h.input(&message);

        k = Scalar::from_hash(h);
        s = &(&k * &self.key) + &r;

        Signature { R, s }
    }

    /// Sign a `prehashed_message` with this `ExpandedSecretKey` using the
    /// Ed25519ph algorithm defined in [RFC8032 §5.1][rfc8032].
    ///
    /// # Inputs
    ///
    /// * `prehashed_message` is an instantiated hash digest with 512-bits of
    ///   output which has had the message to be signed previously fed into its
    ///   state.
    /// * `public_key` is a [`PublicKey`] which corresponds to this secret key.
    /// * `context` is an optional context string, up to 255 bytes inclusive,
    ///   which may be used to provide additional domain separation.  If not
    ///   set, this will default to an empty string.
    ///
    /// # Returns
    ///
    /// An Ed25519ph [`Signature`] on the `prehashed_message`.
    ///
    /// [rfc8032]: https://tools.ietf.org/html/rfc8032#section-5.1
    #[allow(non_snake_case)]
    pub fn sign_prehashed<D>(
        &self,
        prehashed_message: D,
        public_key: &PublicKey,
        context: Option<&'static [u8]>,
    ) -> Signature
    where
        D: Digest<OutputSize = U64>,
    {
        let mut h: Sha512;
        let mut prehash: [u8; 64] = [0u8; 64];
        let R: CompressedEdwardsY;
        let r: Scalar;
        let s: Scalar;
        let k: Scalar;

        let ctx: &[u8] = context.unwrap_or(b""); // By default, the context is an empty string.

        debug_assert!(ctx.len() <= 255, "The context must not be longer than 255 octets.");

        let ctx_len: u8 = ctx.len() as u8;

        // Get the result of the pre-hashed message.
        prehash.copy_from_slice(prehashed_message.result().as_slice());

        // This is the dumbest, ten-years-late, non-admission of fucking up the
        // domain separation I have ever seen.  Why am I still required to put
        // the upper half "prefix" of the hashed "secret key" in here?  Why
        // can't the user just supply their own nonce and decide for themselves
        // whether or not they want a deterministic signature scheme?  Why does
        // the message go into what's ostensibly the signature domain separation
        // hash?  Why wasn't there always a way to provide a context string?
        //
        // ...
        //
        // This is a really fucking stupid bandaid, and the damned scheme is
        // still bleeding from malleability, for fuck's sake.
        h = Sha512::new()
            .chain(b"SigEd25519 no Ed25519 collisions")
            .chain(&[1]) // Ed25519ph
            .chain(&[ctx_len])
            .chain(ctx)
            .chain(&self.nonce)
            .chain(&prehash[..]);

        r = Scalar::from_hash(h);
        R = (&r * &constants::ED25519_BASEPOINT_TABLE).compress();

        h = Sha512::new()
            .chain(b"SigEd25519 no Ed25519 collisions")
            .chain(&[1]) // Ed25519ph
            .chain(&[ctx_len])
            .chain(ctx)
            .chain(R.as_bytes())
            .chain(public_key.as_bytes())
            .chain(&prehash[..]);

        k = Scalar::from_hash(h);
        s = &(&k * &self.key) + &r;

        Signature { R, s }
    }
}

#[cfg(feature = "serde")]
impl Serialize for ExpandedSecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes()[..])
    }
}

#[cfg(feature = "serde")]
impl<'d> Deserialize<'d> for ExpandedSecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        struct ExpandedSecretKeyVisitor;

        impl<'d> Visitor<'d> for ExpandedSecretKeyVisitor {
            type Value = ExpandedSecretKey;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                formatter.write_str(
                    "An ed25519 expanded secret key as 64 bytes, as specified in RFC8032.",
                )
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<ExpandedSecretKey, E>
            where
                E: SerdeError,
            {
                ExpandedSecretKey::from_bytes(bytes)
                    .or(Err(SerdeError::invalid_length(bytes.len(), &self)))
            }
        }
        deserializer.deserialize_bytes(ExpandedSecretKeyVisitor)
    }
}

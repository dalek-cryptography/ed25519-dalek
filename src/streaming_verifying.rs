use crate::{SignatureError, VerifyingKey};
use crate::Signature;
use crate::hazmat;
use sha2::{Sha512, Digest};

pub struct StreamingVerifier {
    /// Public key to verify with.
    pub(crate) public_key: VerifyingKey,

    /// Candidate signature to verify against.
    pub(crate) signature: Signature,

    /// Hash state.
    pub(crate) hasher: Sha512,
}

impl StreamingVerifier {
    // Note: I changed the signature parameter to use Signature
    // instead of InternalSignature, because raw_verify consumes &Signature.
    /// Constructs a new stream verifier.
    ///
    /// Seeds hash state with public key and signature components.
    pub(crate) fn new(public_key: VerifyingKey, signature: Signature) -> Self {
        let mut hasher = Sha512::new();
        hasher.update(signature.r_bytes());
        hasher.update(public_key.as_bytes());

        Self { public_key, hasher, signature }
    }

    // Note: I changed the chunk parameter to use &[u8] instead of
    // impl AsRef<[u8]> because I think it's better. :V
    /// Digest message chunk.
    pub fn update(&mut self, chunk: &[u8]) {
        self.hasher.update(chunk);
    }

    pub fn finalize_and_verify(self) -> Result<(), SignatureError> {
        hazmat::raw_verify::<dirty_workaround::DirtyWorkaround>(&self.public_key, self.hasher.finalize().as_slice(), &self.signature)
    }
}

// So, in normal usage, hazmat::raw_verify uses CtxDigest to hash
// together the things we already did in the process of running through new() and a series
// of update()s.
//
// Here, we workaround the fact that there is no method in hazmat to provide
// that hash already computed (raw_verify_prehashed is not it),
// by making a hasher that plucks out the hash when provided as the message
// inside verifying::compute_challenge().
//
// It would be *much* better if such a method were just added to hazmat,
// as we'd avoid the need for this whole module.
mod dirty_workaround {
    use curve25519_dalek::digest::{Update, FixedOutput, FixedOutputReset, Output, Reset};
    use curve25519_dalek::digest::typenum::Unsigned;
    use curve25519_dalek::digest::generic_array::typenum::U64;
    use sha2::Digest;
    use sha2::digest::OutputSizeUser;

    /// The number of bytes which precede the message
    /// argument to hazmat::raw_verify being fed to this hasher.
    /// It is 2 * (the length of CompressedEdwardsY).
    const PREFIX_BYTES: usize = 64;
    /// The number of bytes which we need to sneak through
    /// the message argument into our hash.
    const HASH_LENGTH: usize = 64;

    pub(crate) struct DirtyWorkaround {
        step: usize,
        hash: [u8; HASH_LENGTH],
    }

    impl Default for DirtyWorkaround {
        fn default() -> Self {
            Self {
                step: 0,
                hash: [0; HASH_LENGTH],
            }
        }
    }

    impl OutputSizeUser for DirtyWorkaround {
        type OutputSize = U64;
    }

    impl Update for DirtyWorkaround {
        fn update(&mut self, data: &[u8]) {
            if self.step >= PREFIX_BYTES && self.step < PREFIX_BYTES + HASH_LENGTH {
                let buf = &mut self.hash[self.step - PREFIX_BYTES..];
                buf.copy_from_slice(data);
            }
            if self.step == PREFIX_BYTES {
                self.hash.copy_from_slice(data.as_ref());
            } else if self.step > PREFIX_BYTES + HASH_LENGTH {
                unreachable!("this should never happen")
            }
            self.step += data.len();
        }
    }

    impl Reset for DirtyWorkaround {
        fn reset(&mut self) {
            self.step = 0;
            self.hash = [0; HASH_LENGTH];
        }
    }

    impl FixedOutput for DirtyWorkaround {
        fn finalize_into(self, out: &mut Output<Self>) {
            out.copy_from_slice(&self.hash);
        }
    }

    impl FixedOutputReset for DirtyWorkaround {
        fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
            out.copy_from_slice(&self.hash);
            <Self as Reset>::reset(self);
        }
    }

    impl Digest for DirtyWorkaround {
        fn new() -> Self {
            Self::default()
        }

        fn new_with_prefix(data: impl AsRef<[u8]>) -> Self {
            let mut hasher = Self::new();
            <Self as Digest>::update(&mut hasher, data);
            hasher
        }

        fn update(&mut self, data: impl AsRef<[u8]>) {
            <Self as Update>::update(self, data.as_ref())
        }

        fn chain_update(mut self, data: impl AsRef<[u8]>) -> Self {
            <Self as Digest>::update(&mut self, data);
            self
        }

        fn finalize(self) -> Output<Self> {
            let mut out = Output::<Self>::default();
            <Self as Digest>::finalize_into(self, &mut out);
            out
        }

        fn finalize_into(self, out: &mut Output<Self>) {
            out.copy_from_slice(&self.hash);
        }

        fn finalize_reset(&mut self) -> Output<Self> where Self: FixedOutputReset {
            <Self as FixedOutputReset>::finalize_fixed_reset(self)
        }

        fn finalize_into_reset(&mut self, out: &mut Output<Self>) where Self: FixedOutputReset {
            <Self as FixedOutputReset>::finalize_into_reset(self, out)
        }

        fn reset(&mut self) where Self: Reset {
            <Self as Reset>::reset(self)
        }

        fn output_size() -> usize {
            Self::OutputSize::to_usize()
        }

        fn digest(data: impl AsRef<[u8]>) -> Output<Self> {
            Self::new_with_prefix(data).finalize()
        }
    }
}
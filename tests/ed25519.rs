// -*- mode: rust; -*-
//
// This file is part of ed25519-dalek.
// Copyright (c) 2017-2019 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! Integration tests for ed25519-dalek.

#[cfg(all(test, feature = "serde"))]
extern crate bincode;
extern crate ed25519_dalek;
extern crate hex;
extern crate rand;

use ed25519_dalek::*;

use hex::FromHex;

use rand::rngs::ThreadRng;
use rand::thread_rng;

#[cfg(test)]
mod vectors {
    #[cfg(not(feature = "sha3"))]
    use std::fs::File;
    #[cfg(not(feature = "sha3"))]
    use std::io::BufRead;
    #[cfg(not(feature = "sha3"))]
    use std::io::BufReader;

    use super::*;

    // TESTVECTORS is taken from sign.input.gz in agl's ed25519 Golang
    // package. It is a selection of test cases from
    // http://ed25519.cr.yp.to/python/sign.input
    #[cfg(not(feature = "sha3"))]
    #[test]
    fn against_reference_implementation() {
        // TestGolden
        let mut line: String;
        let mut lineno: usize = 0;

        let f = File::open("TESTVECTORS");
        if f.is_err() {
            println!(
                "This test is only available when the code has been cloned \
                 from the git repository, since the TESTVECTORS file is large \
                 and is therefore not included within the distributed crate."
            );
            panic!();
        }
        let file = BufReader::new(f.unwrap());

        for l in file.lines() {
            lineno += 1;
            line = l.unwrap();

            let parts: Vec<&str> = line.split(':').collect();
            assert_eq!(parts.len(), 5, "wrong number of fields in line {}", lineno);

            let sec_bytes: Vec<u8> = FromHex::from_hex(&parts[0]).unwrap();
            let pub_bytes: Vec<u8> = FromHex::from_hex(&parts[1]).unwrap();
            let msg_bytes: Vec<u8> = FromHex::from_hex(&parts[2]).unwrap();
            let sig_bytes: Vec<u8> = FromHex::from_hex(&parts[3]).unwrap();

            let secret: SecretKey = SecretKey::from_bytes(&sec_bytes[..SECRET_KEY_LENGTH]).unwrap();
            let public: PublicKey = PublicKey::from_bytes(&pub_bytes[..PUBLIC_KEY_LENGTH]).unwrap();
            let keypair: Keypair = Keypair {
                secret: secret,
                public: public,
            };

            // The signatures in the test vectors also include the message
            // at the end, but we just want R and S.
            let sig1: Signature = Signature::from_bytes(&sig_bytes[..64]).unwrap();
            let sig2: Signature = keypair.sign(&msg_bytes);

            assert!(sig1 == sig2, "Signature bytes not equal on line {}", lineno);
            assert!(
                keypair.verify(&msg_bytes, &sig2).is_ok(),
                "Signature verification failed on line {}",
                lineno
            );
        }
    }

    // From https://tools.ietf.org/html/rfc8032#section-7.3
    #[test]
    fn ed25519ph_rf8032_test_vector() {
        let secret_key: &[u8] = b"833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42";
        let message: &[u8] = b"616263";

        #[cfg(not(feature = "sha3"))]
        let public_key: &[u8] = b"ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf";

        #[cfg(feature = "sha3")]
        let public_key: &[u8] = b"5a9d6b3944aa1f6281b3f3a0e340ab16f88e415c0b57ab257fc05d5d0220c705";

        #[cfg(not(feature = "sha3"))]
        let signature: &[u8] = b"98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406";

        #[cfg(feature = "sha3")]
        let signature: &[u8] = b"3ab65cc6cb601715fdc77a71c4e2b8340ca33099920757229e1211d4c79c42f573569e1b156f15a6b2dfe0e3ca23187820f258defaa5584bd338e7cd02b73003";

        let sec_bytes: Vec<u8> = FromHex::from_hex(secret_key).unwrap();
        let pub_bytes: Vec<u8> = FromHex::from_hex(public_key).unwrap();
        let msg_bytes: Vec<u8> = FromHex::from_hex(message).unwrap();
        let sig_bytes: Vec<u8> = FromHex::from_hex(signature).unwrap();

        let secret: SecretKey = SecretKey::from_bytes(&sec_bytes[..SECRET_KEY_LENGTH]).unwrap();
        let public: PublicKey = PublicKey::from_bytes(&pub_bytes[..PUBLIC_KEY_LENGTH]).unwrap();
        let keypair: Keypair = Keypair {
            secret: secret,
            public: public,
        };
        let sig1: Signature = Signature::from_bytes(&sig_bytes[..]).unwrap();

        let mut prehash_for_signing: Sha512 = Sha512::default();
        let mut prehash_for_verifying: Sha512 = Sha512::default();

        prehash_for_signing.input(&msg_bytes[..]);
        prehash_for_verifying.input(&msg_bytes[..]);

        let sig2: Signature = keypair.sign_prehashed(prehash_for_signing, None);

        assert!(
            sig1 == sig2,
            "Original signature from test vectors doesn't equal signature produced:\
             \noriginal:\n{:?}\nproduced:\n{:?}",
            sig1,
            sig2
        );
        assert!(
            keypair
                .verify_prehashed(prehash_for_verifying, None, &sig2)
                .is_ok(),
            "Could not verify ed25519ph signature!"
        );
    }
}

#[cfg(test)]
mod integrations {
    use super::*;

    #[test]
    fn sign_verify() {
        // TestSignVerify
        let mut csprng: ThreadRng;
        let keypair: Keypair;
        let good_sig: Signature;
        let bad_sig: Signature;

        let good: &[u8] = "test message".as_bytes();
        let bad: &[u8] = "wrong message".as_bytes();

        csprng = thread_rng();
        keypair = Keypair::generate(&mut csprng);
        good_sig = keypair.sign(&good);
        bad_sig = keypair.sign(&bad);

        assert!(
            keypair.verify(&good, &good_sig).is_ok(),
            "Verification of a valid signature failed!"
        );
        assert!(
            keypair.verify(&good, &bad_sig).is_err(),
            "Verification of a signature on a different message passed!"
        );
        assert!(
            keypair.verify(&bad, &good_sig).is_err(),
            "Verification of a signature on a different message passed!"
        );
    }

    #[test]
    fn ed25519ph_sign_verify() {
        let mut csprng: ThreadRng;
        let keypair: Keypair;
        let good_sig: Signature;
        let bad_sig: Signature;

        let good: &[u8] = b"test message";
        let bad: &[u8] = b"wrong message";

        // ugh… there's no `impl Copy for Sha512`… i hope we can all agree these are the same hashes
        let mut prehashed_good1: Sha512 = Sha512::default();
        prehashed_good1.input(good);
        let mut prehashed_good2: Sha512 = Sha512::default();
        prehashed_good2.input(good);
        let mut prehashed_good3: Sha512 = Sha512::default();
        prehashed_good3.input(good);

        let mut prehashed_bad1: Sha512 = Sha512::default();
        prehashed_bad1.input(bad);
        let mut prehashed_bad2: Sha512 = Sha512::default();
        prehashed_bad2.input(bad);

        let context: &[u8] = b"testing testing 1 2 3";

        csprng = thread_rng();
        keypair = Keypair::generate(&mut csprng);
        good_sig = keypair.sign_prehashed(prehashed_good1, Some(context));
        bad_sig = keypair.sign_prehashed(prehashed_bad1, Some(context));

        assert!(
            keypair
                .verify_prehashed(prehashed_good2, Some(context), &good_sig)
                .is_ok(),
            "Verification of a valid signature failed!"
        );
        assert!(
            keypair
                .verify_prehashed(prehashed_good3, Some(context), &bad_sig)
                .is_err(),
            "Verification of a signature on a different message passed!"
        );
        assert!(
            keypair
                .verify_prehashed(prehashed_bad2, Some(context), &good_sig)
                .is_err(),
            "Verification of a signature on a different message passed!"
        );
    }

    #[test]
    fn verify_batch_seven_signatures() {
        let messages: [&[u8]; 7] = [
            b"Watch closely everyone, I'm going to show you how to kill a god.",
            b"I'm not a cryptographer I just encrypt a lot.",
            b"Still not a cryptographer.",
            b"This is a test of the tsunami alert system. This is only a test.",
            b"Fuck dumbin' it down, spit ice, skip jewellery: Molotov cocktails on me like accessories.",
            b"Hey, I never cared about your bucks, so if I run up with a mask on, probably got a gas can too.",
            b"And I'm not here to fill 'er up. Nope, we came to riot, here to incite, we don't want any of your stuff.", ];
        let mut csprng: ThreadRng = thread_rng();
        let mut keypairs: Vec<Keypair> = Vec::new();
        let mut signatures: Vec<Signature> = Vec::new();

        for i in 0..messages.len() {
            let keypair: Keypair = Keypair::generate(&mut csprng);
            signatures.push(keypair.sign(&messages[i]));
            keypairs.push(keypair);
        }
        let public_keys: Vec<PublicKey> = keypairs.iter().map(|key| key.public).collect();

        let result = verify_batch(&messages, &signatures[..], &public_keys[..]);

        assert!(result.is_ok());
    }

    #[test]
    fn pubkey_from_secret_and_expanded_secret() {
        let mut csprng = thread_rng();
        let secret: SecretKey = SecretKey::generate(&mut csprng);
        let expanded_secret: ExpandedSecretKey = (&secret).into();
        let public_from_secret: PublicKey = (&secret).into(); // XXX eww
        let public_from_expanded_secret: PublicKey = (&expanded_secret).into(); // XXX eww

        assert!(public_from_secret == public_from_expanded_secret);
    }
}

#[cfg(all(test, feature = "serde"))]
mod serialisation {
    use super::*;

    use self::bincode::{deserialize, serialize, serialized_size, Infinite};

    static PUBLIC_KEY_BYTES: [u8; PUBLIC_KEY_LENGTH] = [
        130, 039, 155, 015, 062, 076, 188, 063, 124, 122, 026, 251, 233, 253, 225, 220, 014, 041,
        166, 120, 108, 035, 254, 077, 160, 083, 172, 058, 219, 042, 086, 120,
    ];

    static SECRET_KEY_BYTES: [u8; SECRET_KEY_LENGTH] = [
        062, 070, 027, 163, 092, 182, 011, 003, 077, 234, 098, 004, 011, 127, 079, 228, 243, 187,
        150, 073, 201, 137, 076, 022, 085, 251, 152, 002, 241, 042, 072, 054,
    ];

    /// Signature with the above keypair of a blank message.
    static SIGNATURE_BYTES: [u8; SIGNATURE_LENGTH] = [
        010, 126, 151, 143, 157, 064, 047, 001, 196, 140, 179, 058, 226, 152, 018, 102, 160, 123,
        080, 016, 210, 086, 196, 028, 053, 231, 012, 157, 169, 019, 158, 063, 045, 154, 238, 007,
        053, 185, 227, 229, 079, 108, 213, 080, 124, 252, 084, 167, 216, 085, 134, 144, 129, 149,
        041, 081, 063, 120, 126, 100, 092, 059, 050, 011,
    ];

    #[test]
    fn serialize_deserialize_signature() {
        let signature: Signature = Signature::from_bytes(&SIGNATURE_BYTES).unwrap();
        let encoded_signature: Vec<u8> = serialize(&signature, Infinite).unwrap();
        let decoded_signature: Signature = deserialize(&encoded_signature).unwrap();

        assert_eq!(signature, decoded_signature);
    }

    #[test]
    fn serialize_deserialize_public_key() {
        let public_key: PublicKey = PublicKey::from_bytes(&PUBLIC_KEY_BYTES).unwrap();
        let encoded_public_key: Vec<u8> = serialize(&public_key, Infinite).unwrap();
        let decoded_public_key: PublicKey = deserialize(&encoded_public_key).unwrap();

        assert_eq!(
            &PUBLIC_KEY_BYTES[..],
            &encoded_public_key[encoded_public_key.len() - 32..]
        );
        assert_eq!(public_key, decoded_public_key);
    }

    #[test]
    fn serialize_deserialize_secret_key() {
        let secret_key: SecretKey = SecretKey::from_bytes(&SECRET_KEY_BYTES).unwrap();
        let encoded_secret_key: Vec<u8> = serialize(&secret_key, Infinite).unwrap();
        let decoded_secret_key: SecretKey = deserialize(&encoded_secret_key).unwrap();

        for i in 0..32 {
            assert_eq!(SECRET_KEY_BYTES[i], decoded_secret_key.as_bytes()[i]);
        }
    }

    #[test]
    fn serialize_public_key_size() {
        let public_key: PublicKey = PublicKey::from_bytes(&PUBLIC_KEY_BYTES).unwrap();
        assert_eq!(serialized_size(&public_key) as usize, 40); // These sizes are specific to bincode==1.0.1
    }

    #[test]
    fn serialize_signature_size() {
        let signature: Signature = Signature::from_bytes(&SIGNATURE_BYTES).unwrap();
        assert_eq!(serialized_size(&signature) as usize, 72); // These sizes are specific to bincode==1.0.1
    }

    #[test]
    fn serialize_secret_key_size() {
        let secret_key: SecretKey = SecretKey::from_bytes(&SECRET_KEY_BYTES).unwrap();
        assert_eq!(serialized_size(&secret_key) as usize, 40); // These sizes are specific to bincode==1.0.1
    }
}

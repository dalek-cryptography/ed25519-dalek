# ed25519-dalek [![](https://img.shields.io/crates/v/ed25519-dalek.svg)](https://crates.io/crates/ed25519-dalek) [![](https://docs.rs/ed25519-dalek/badge.svg)](https://docs.rs/ed25519-dalek) [![](https://travis-ci.org/dalek-cryptography/ed25519-dalek.svg?branch=master)](https://travis-ci.org/dalek-cryptography/ed25519-dalek?branch=master)

Fast and efficient Rust implementation of ed25519 key generation, signing, and
verification in Rust.

# Documentation

Documentation is available [here](https://docs.rs/ed25519-dalek).

# Installation

To install, add the following to your project's `Cargo.toml`:

```toml
[dependencies.ed25519-dalek]
version = "1"
```

# Minimum Supported Rust Version

This crate requires Rust 1.56.1 at a minimum. 1.x releases of this crate supported an MSRV of 1.41.

In the future, MSRV changes will be accompanied by a minor version bump.

# Changelog

See [CHANGELOG.md](CHANGELOG.md) for a list of changes made in past version of this crate.

# Benchmarks

On an Intel 10700K running at stock comparing between the `curve25519-dalek` backends.

**u64**: The default `serial` backend with `u64` target backend
$ `cargo bench --features batch`

**simd +avx2**: The `simd` backend with the `avx2` target backend
$ `export RUSTFLAGS='--cfg curve25519_dalek_backend="simd" -C target_feature=+avx2'`

**fiat**: The `fiat` formally verified backend
$ `export RUSTFLAGS='--cfg curve25519_dalek_backend="fiat"

| Benchmark                       | u64       | simd +avx2         | fiat               |
| :---                            | :----     | :---               | :---               |
| signing                         | 15.017 µs | 13.906 µs -7.3967% | 15.877 µs +14.188% |
| signature verification          | 40.144 µs | 25.963 µs -35.603% | 42.118 µs +62.758% |
| strict signature verification   | 41.334 µs | 27.874 µs -32.660% | 43.985 µs +57.763% |
| batch signature verification/4  | 109.44 µs | 81.778 µs -25.079% | 117.80 µs +43.629% |
| batch signature verification/8  | 182.75 µs | 138.40 µs -23.871% | 195.86 µs +40.665% |
| batch signature verification/16 | 328.67 µs | 251.39 µs -23.744% | 351.55 µs +39.901% |
| batch signature verification/32 | 619.49 µs | 477.36 µs -23.053% | 669.41 µs +39.966% |
| batch signature verification/64 | 1.2136 ms | 936.85 µs -22.543% | 1.3028 ms +38.808% |
| batch signature verification/96 | 1.8677 ms | 1.2357 ms -33.936% | 2.0552 ms +66.439% |
| batch signature verification/128| 2.3281 ms | 1.5795 ms -31.996% | 2.5596 ms +61.678% |
| batch signature verification/256| 4.1868 ms | 2.8864 ms -31.061% | 4.6494 ms +61.081% |
| keypair generation              | 13.973 µs | 13.108 µs -6.5062% | 15.099 µs +15.407% |

See more information about the used [curve25519-dalek backends](https//docs.rs/curve25519-dalek) to determine the right for your you.

Making key generation and signing a rough average of 2x faster, and
verification 2.5-3x faster depending on the availability of avx2.  Of course, this
is just my machine, and these results—nowhere near rigorous—should be taken
with a handful of salt.

Translating to a rough cycle count: we multiply by a factor of 3.3 to convert
nanoseconds to cycles per second on a 3300 Mhz CPU, that's 110256 cycles for
verification and 52618 for signing, which is competitive with hand-optimised
assembly implementations.

Additionally, if you're using a CSPRNG from the `rand` crate, the `nightly`
feature will enable `u128`/`i128` features there, resulting in potentially
faster performance.

If your protocol or application is able to batch signatures for verification,
the `verify_batch()` function has greatly improved performance.  On the
aforementioned Intel Skylake i9-7900X, verifying a batch of 96 signatures takes
1.7673ms.  That's 18.4094us, or roughly 60750 cycles, per signature verification,
more than double the speed of batch verification given in the original paper
(this is likely not a fair comparison as that was a Nehalem machine).
The numbers after the `/` in the test name refer to the size of the batch:

As you can see, there's an optimal batch size for each machine, so you'll likely
want to test the benchmarks on your target CPU to discover the best size.  For
this machine, around 100 signatures per batch is the optimum:

![](https://github.com/dalek-cryptography/ed25519-dalek/blob/master/res/batch-violin-benchmark.svg)

Additionally, thanks to Rust, this implementation has both type and memory
safety.  It's also easily readable by a much larger set of people than those who
can read qhasm, making it more readily and more easily auditable.  We're of
the opinion that, ultimately, these features—combined with speed—are more
valuable than simply cycle counts alone.

# A Note on Signature Malleability

The signatures produced by this library are malleable, as discussed in
[the original paper](https://ed25519.cr.yp.to/ed25519-20110926.pdf):

![](https://github.com/dalek-cryptography/ed25519-dalek/blob/master/res/ed25519-malleability.png)

While the scalar component of our `Signature` struct is strictly *not*
malleable, because reduction checks are put in place upon `Signature`
deserialisation from bytes, for all types of signatures in this crate,
there is still the question of potential malleability due to the group
element components.

We could eliminate the latter malleability property by multiplying by the curve
cofactor, however, this would cause our implementation to *not* match the
behaviour of every other implementation in existence.  As of this writing,
[RFC 8032](https://tools.ietf.org/html/rfc8032), "Edwards-Curve Digital
Signature Algorithm (EdDSA)," advises that the stronger check should be done.
While we agree that the stronger check should be done, it is our opinion that
one shouldn't get to change the definition of "ed25519 verification" a decade
after the fact, breaking compatibility with every other implementation.

However, if you require this, please see the documentation for the
`verify_strict()` function, which does the full checks for the group elements.
This functionality is available by default.

If for some reason—although we strongly advise you not to—you need to conform
to the original specification of ed25519 signatures as in the excerpt from the
paper above, you can disable scalar malleability checking via
`--features='legacy_compatibility'`.  **WE STRONGLY ADVISE AGAINST THIS.**

## The `legacy_compatibility` Feature

By default, this library performs a stricter check for malleability in the
scalar component of a signature, upon signature deserialisation.  This stricter
check, that `s < \ell` where `\ell` is the order of the basepoint, is
[mandated by RFC8032](https://tools.ietf.org/html/rfc8032#section-5.1.7).
However, that RFC was standardised a decade after the original paper, which, as
described above, (usually, falsely) stated that malleability was inconsequential.

Because of this, most ed25519 implementations only perform a limited, hackier
check that the most significant three bits of the scalar are unset.  If you need
compatibility with legacy implementations, including:

* ed25519-donna
* Golang's /x/crypto ed25519
* libsodium (only when built with `-DED25519_COMPAT`)
* NaCl's "ref" implementation
* probably a bunch of others

then enable `ed25519-dalek`'s `legacy_compatibility` feature.  Please note and
be forewarned that doing so allows for signature malleability, meaning that
there may be two different and "valid" signatures with the same key for the same
message, which is obviously incredibly dangerous in a number of contexts,
including—but not limited to—identification protocols and cryptocurrency
transactions.

## The `verify_strict()` Function

The scalar component of a signature is not the only source of signature
malleability, however.  Both the public key used for signature verification and
the group element component of the signature are malleable, as they may contain
a small torsion component as a consquence of the curve25519 group not being of
prime order, but having a small cofactor of 8.

If you wish to also eliminate this source of signature malleability, please
review the
[documentation for the `verify_strict()` function](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/struct.PublicKey.html#method.verify_strict).

# A Note on Randomness Generation

The original paper's specification and the standarisation of RFC8032 do not
specify precisely how randomness is to be generated, other than using a CSPRNG
(Cryptographically Secure Random Number Generator).  Particularly in the case of
signature verification, where the security proof _relies_ on the uniqueness of
the blinding factors/nonces, it is paramount that these samples of randomness be
unguessable to an adversary.  Because of this, a current growing belief among
cryptographers is that it is safer to prefer _synthetic randomness_.

To explain synthetic randomness, we should first explain how `ed25519-dalek`
handles generation of _deterministic randomness_.  This mode is disabled by
default due to a tiny-but-not-nonexistent chance that this mode will open users
up to fault attacks, wherein an adversary who controls all of the inputs to
batch verification (i.e. the public keys, signatures, and messages) can craft
them in a specialised manner such as to induce a fault (e.g. causing a
mistakenly flipped bit in RAM, overheating a processor, etc.).  In the
deterministic mode, we seed the PRNG which generates our blinding factors/nonces
by creating
[a PRNG based on the Fiat-Shamir transform of the public inputs](https://merlin.cool/transcript/rng.html).
This mode is potentially useful to protocols which require strong auditability
guarantees, as well as those which do not have access to secure system-/chip-
provided randomness.  This feature can be enabled via
`--features='batch_deterministic'`.  Note that we _do not_ support deterministic
signing, due to the numerous pitfalls therein, including a re-used nonce
accidentally revealing the secret key.

In the default mode, we do as above in the fully deterministic mode, but we
ratchet the underlying keccak-f1600 function (used for the provided
transcript-based PRNG) forward additionally based on some system-/chip- provided
randomness.  This provides _synthetic randomness_, that is, randomness based on
both deterministic and undeterinistic data.  The reason for doing this is to
prevent badly seeded system RNGs from ruining the security of the signature
verification scheme.

# Features

## #![no_std]

This library aims to be `#![no_std]` compliant.  If batch verification is
required (`--features='batch'`), please enable either of the `std` or `alloc`
features.

## Nightly Compilers

To cause your application to build `ed25519-dalek` with the nightly feature
enabled by default, instead do:

```toml
[dependencies.ed25519-dalek]
version = "1"
features = ["nightly"]
```

To cause your application to instead build with the nightly feature enabled
when someone builds with `cargo build --features="nightly"` add the following
to the `Cargo.toml`:

```toml
[features]
nightly = ["ed25519-dalek/nightly"]
```

## Serde

To enable [serde](https://serde.rs) support, build `ed25519-dalek` with the
`serde` feature.

## (Micro)Architecture Specific Backends

`ed25519-dalek` uses the backends from the `curve25519-dalek` crate.

By default the serial backend is used and depending on the target
platform either the 32 bit or the 64 bit serial formula is automatically used.

To address variety of  usage scenarios various backends are available that
include hardware optimisations as well as a formally verified fiat crypto
backend that does not use any hardware optimisations.

These backends can be overriden with various configuration predicates (cfg)

Please see the [curve25519_dalek backend documentation](https://docs.rs/curve25519-dalek/latest/curve25519_dalek).

## Batch Signature Verification

The standard variants of batch signature verification (i.e. many signatures made
with potentially many different public keys over potentially many different
message) is available via the `batch` feature.  It uses synthetic randomness, as
noted above.

### Deterministic Batch Signature Verification

The same notion of batch signature verification as above, but with purely
deterministic randomness can be enabled via the `batch_deterministic` feature.

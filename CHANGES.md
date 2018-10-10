## [0.9.4] (2018-10-10)

[0.9.4]: https://github.com/tendermint/signatory/pull/126

* [#125](https://github.com/tendermint/signatory/pull/125)
  pkcs8: Properly gate `FILE_MODE` on Windows.

## [0.9.3] (2018-10-09)

[0.9.3]: https://github.com/tendermint/signatory/pull/124

* [#123](https://github.com/tendermint/signatory/pull/123)
  Upgrade to subtle-encoding v0.2.

* [#122](https://github.com/tendermint/signatory/pull/122)
  Fix unused import on Windows (closes #121).

## [0.9.2] (2018-10-08)

[0.9.2]: https://github.com/tendermint/signatory/pull/118

* [#117](https://github.com/tendermint/signatory/pull/117)
  More documentation fixups.

## [0.9.1] (2018-10-08)

[0.9.1]: https://github.com/tendermint/signatory/pull/116

* [#115](https://github.com/tendermint/signatory/pull/115)
  Cargo.toml: Fix docs.rs build.

## [0.9.0] (2018-10-08)

[0.9.0]: https://github.com/tendermint/signatory/pull/114

* [#112](https://github.com/tendermint/signatory/pull/112)
  Remove redundant "namespacing" from type names.

* [#111](https://github.com/tendermint/signatory/pull/111)
  Move `curve` module (back) under `ecdsa`.

* [#110](https://github.com/tendermint/signatory/pull/109)
  signatory-yubihsm: Upgrade to yubihsm 0.18.

* [#109](https://github.com/tendermint/signatory/pull/109)
  Use `subtle-encoding` crate for constant-time encoding/decoding.

* [#108](https://github.com/tendermint/signatory/pull/108)
  ECDSA `SecretKey` type and related traits (e.g. `GeneratePkcs8`).

* [#106](https://github.com/tendermint/signatory/pull/106)
  Properly handle leading zeroes in ASN.1 serialization/parsing.

* [#105](https://github.com/tendermint/signatory/pull/106)
  signatory-yubihsm: Expose the yubihsm crate as a pub extern.

* [#102](https://github.com/tendermint/signatory/pull/102)
  encoding: Use 0o600 file mode on Unix.

* [#97](https://github.com/tendermint/signatory/pull/97)
  Eliminate `ed25519::FromSeed` trait.

* [#94](https://github.com/tendermint/signatory/pull/94)
  yubihsm: NIST P-384 support.

* [#91](https://github.com/tendermint/signatory/pull/94)
  ring: NIST P-384 support.

* [#89](https://github.com/tendermint/signatory/pull/89)
  Add NIST P-384 elliptic curve type (closes #73).

* [#88](https://github.com/tendermint/signatory/pull/88)
  signatory-yubihsm: Fix ECDSA over secp256k1 signing (closes #87).

* [#80](https://github.com/tendermint/signatory/pull/80)
  `signatory-ledger-cosval` provider.

* [#79](https://github.com/tendermint/signatory/pull/79)
  signatory-yubihsm: Normalize secp256k1 signatures to "low S" form.

* [#78](https://github.com/tendermint/signatory/pull/78)
  signatory-secp256k1: Bump secp256k1 crate dependency to 0.11

* [#76](https://github.com/tendermint/signatory/pull/76)
  Unify verification API under the `Verifier` trait.

* [#74](https://github.com/tendermint/signatory/pull/74)
  encoding: Add encoding module with hex and Base64 support.

* [#70](https://github.com/tendermint/signatory/pull/70)
  Unify signing API under the `Signer` trait.

## [0.8.0] (2018-08-19)

[0.8.0]: https://github.com/tendermint/signatory/compare/v0.7.0...v0.8.0

* [#67](https://github.com/tendermint/signatory/pull/67)
  Extract 'from_pkcs8' into a trait.

* [#65](https://github.com/tendermint/signatory/pull/65)
  signatory-yubihsm: Make ecdsa and ed25519 modules public.

## [0.7.0] (2018-08-19)

[0.7.0]: https://github.com/tendermint/signatory/compare/v0.6.1...v0.7.1

* [#63](https://github.com/tendermint/signatory/pull/63)
  Factor providers into their own 'signatory-*' crates.

* [#62](https://github.com/tendermint/signatory/pull/62)
  Unify ECDSA traits across DER and fixed-sized signatures.

* [#61](https://github.com/tendermint/signatory/pull/61)
  ECDSA DER signature parsing and serialization.

## [0.6.1] (2018-07-31)

[0.6.1]: https://github.com/tendermint/signatory/compare/v0.6.0...v0.6.1

* [#59](https://github.com/tendermint/signatory/pull/59)
  Upgrade to `secp256k1` crate v0.10.

## [0.6.0] (2018-07-31)

[0.6.0]: https://github.com/tendermint/signatory/compare/v0.5.2...v0.6.0

* [#56](https://github.com/tendermint/signatory/pull/56)
  Factor ECDSA PublicKey into compressed/uncompressed curve points.

* [#55](https://github.com/tendermint/signatory/pull/55)
  ECDSA support for `yubihsm-provider`.

* [#54](https://github.com/tendermint/signatory/pull/54)
  Upgrade to `yubihsm` crate 0.14.

* [#53](https://github.com/tendermint/signatory/pull/53)
  Add Rustdoc logo.

* [#52](https://github.com/tendermint/signatory/pull/52)
  Audit project for security vulnerabilities with cargo-audit.

* [#51](https://github.com/tendermint/signatory/pull/49)
  Update to ed25519-dalek 0.8.

* [#49](https://github.com/tendermint/signatory/pull/49)
  Add ECDSA NIST P-256 support with *ring* provider.

* [#46](https://github.com/tendermint/signatory/pull/46)
  Factor ECDSA traits apart into separate traits per method.

* [#40](https://github.com/tendermint/signatory/pull/40)
  Upgrade to sodiumoxide 0.1.

* [#38](https://github.com/tendermint/signatory/pull/38)
  Add `ed25519::Seed::from_keypair` method

* [#37](https://github.com/tendermint/signatory/pull/37)
  No default features.

* [#35](https://github.com/tendermint/signatory/pull/35)
  Add `ed25519::Seed` type.

## [0.5.2] (2018-05-19)

[0.5.2]: https://github.com/tendermint/signatory/compare/v0.5.1...v0.5.2

* [#32](https://github.com/tendermint/signatory/pull/32)
  Update to yubihsm-rs 0.9.

* [#30](https://github.com/tendermint/signatory/pull/30)
  Fix benchmarks.

## [0.5.1] (2018-04-13)

[0.5.1]: https://github.com/tendermint/signatory/compare/v0.5.0...v0.5.1

* [#29](https://github.com/tendermint/signatory/pull/29)
  Mark all Signers and Verifiers as Send safe.

## [0.5.0] (2018-04-12)

[0.5.0]: https://github.com/tendermint/signatory/compare/v0.4.1...v0.5.0

* [#27](https://github.com/tendermint/signatory/pull/27)
  Upgrade to yubihsm-rs 0.8.

* [#26](https://github.com/tendermint/signatory/pull/26)
  ECDSA verification support.

* [#25](https://github.com/tendermint/signatory/pull/25)
  ECDSA support with secp256k1 provider.

* [#24](https://github.com/tendermint/signatory/pull/24)
  Ed25519 FromSeed trait and miscellaneous cleanups.

* [#21](https://github.com/tendermint/signatory/pull/21)
  Remove unnecessary direct dependency on curve25519-dalek

## [0.4.1] (2018-04-05)

[0.4.1]: https://github.com/tendermint/signatory/compare/v0.4.0...v0.4.1

* [#20](https://github.com/tendermint/signatory/pull/20)
  Add more bounds to the Verifier trait.

## [0.4.0] (2018-04-05)

[0.4.0]: https://github.com/tendermint/signatory/compare/v0.3.2...v0.4.0

* [#19](https://github.com/tendermint/signatory/pull/19)
  Add an "ed25519" module to all providers.

* [#18](https://github.com/tendermint/signatory/pull/18)
  sodiumoxide provider for Ed25519.
  
* [#17](https://github.com/tendermint/signatory/pull/17)
  *ring* provider for Ed25519.

* [#16](https://github.com/tendermint/signatory/pull/16)
  ed25519::Verifier trait.

## [0.3.2] (2018-03-31)

[0.3.2]: https://github.com/tendermint/signatory/compare/v0.3.1...v0.3.2

* [#15](https://github.com/tendermint/signatory/pull/15)
  Upgrade ed25519-dalek to 0.6.2.

## [0.3.1] (2018-03-27)

[0.3.1]: https://github.com/tendermint/signatory/compare/v0.3.0...v0.3.1

* [#14](https://github.com/tendermint/signatory/pull/14)
  Update to yubihsm-rs 0.7.

## [0.3.0] (2018-03-20)

[0.3.0]: https://github.com/tendermint/signatory/compare/v0.2.0...v0.3.0

* [#13](https://github.com/tendermint/signatory/pull/13)
  Refactor providers + `yubihsm-rs` update + `Sync`-safe signers.

## [0.2.0] (2018-03-13)

[0.2.0]: https://github.com/tendermint/signatory/compare/v0.1.0...v0.2.0

* [#12](https://github.com/tendermint/signatory/pull/12)
  Add `ed25519::Signer::public_key()`.

## 0.1.0 (2018-03-12)

* Initial release

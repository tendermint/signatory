## [0.10.0] (2018-10-16)

- Upgrade to `digest` 0.8, `generic-array` 0.12, and `yubihsm` 0.19 (#130)
- Upgrade to `zeroize` 0.4 (#129)

## [0.9.4] (2018-10-10)

- pkcs8: Properly gate `FILE_MODE` on Windows (#125)

## [0.9.3] (2018-10-09)

- Upgrade to subtle-encoding v0.2 (#123)
- Fix unused import on Windows (closes #121) (#122)

## [0.9.2] (2018-10-08)

- More documentation fixups (#117)

## [0.9.1] (2018-10-08)

- Cargo.toml: Fix docs.rs build (#115)

## [0.9.0] (2018-10-08)

- Remove redundant "namespacing" from type names (#112)
- Move `curve` module (back) under `ecdsa` (#111)
- signatory-yubihsm: Upgrade to yubihsm 0.18 (#110)
- Use `subtle-encoding` crate for constant-time encoding/decoding (#109)
- ECDSA `SecretKey` type and related traits (e.g. `GeneratePkcs8`) (#108)
- Properly handle leading zeroes in ASN.1 serialization/parsing (#106)
- signatory-yubihsm: Expose the yubihsm crate as a pub extern (#105)
- encoding: Use 0o600 file mode on Unix (#102)
- Eliminate `ed25519::FromSeed` trait (#97)
- yubihsm: NIST P-384 support (#94)
- ring: NIST P-384 support (#91)
- Add NIST P-384 elliptic curve type (closes #73) (#89)
- signatory-yubihsm: Fix ECDSA over secp256k1 signing (closes #87) (#88)
- `signatory-ledger-cosval` provider (#80)
- signatory-yubihsm: Normalize secp256k1 signatures to "low S" form (#79)
- signatory-secp256k1: Bump secp256k1 crate dependency to 0.11 (#78)
- Unify verification API under the `Verifier` trait (#76)
- encoding: Add encoding module with hex and Base64 support (#74)
- Unify signing API under the `Signer` trait (#70)

## [0.8.0] (2018-08-19)

- Extract 'from_pkcs8' into a trait (#67)
- signatory-yubihsm: Make ecdsa and ed25519 modules public (#65)

## [0.7.0] (2018-08-19)

- Factor providers into their own 'signatory-*' crates (#63)
- Unify ECDSA traits across DER and fixed-sized signatures (#62)
- ECDSA DER signature parsing and serialization (#61)

## [0.6.1] (2018-07-31)

- Upgrade to `secp256k1` crate v0.10 (#59)

## [0.6.0] (2018-07-31)

- Factor ECDSA PublicKey into compressed/uncompressed curve points (#56)
- ECDSA support for `yubihsm-provider` (#55)
- Upgrade to `yubihsm` crate 0.14 (#54)
- Add Rustdoc logo (#53)
- Audit project for security vulnerabilities with cargo-audit (#52)
- Update to ed25519-dalek 0.8 (#51)
- Add ECDSA NIST P-256 support with *ring* provider (#49)
- Factor ECDSA traits apart into separate traits per method (#46)
- Upgrade to sodiumoxide 0.1 (#40)
- Add `ed25519::Seed::from_keypair` method (#38)
- No default features (#37)
- Add `ed25519::Seed` type (#35)

## [0.5.2] (2018-05-19)

- Update to yubihsm-rs 0.9 (#32)
- Fix benchmarks (#30)

## [0.5.1] (2018-04-13)

- Mark all Signers and Verifiers as Send safe (#29)

## [0.5.0] (2018-04-12)

- Upgrade to yubihsm-rs 0.8 (#27)
- ECDSA verification support (#26)
- ECDSA support with secp256k1 provider (#25)
- Ed25519 FromSeed trait and miscellaneous cleanups (#24)
- Remove unnecessary direct dependency on curve25519-dalek (#12)

## [0.4.1] (2018-04-05)

- Add more bounds to the Verifier trait (#20)

## [0.4.0] (2018-04-05)

- Add an "ed25519" module to all providers (#19)
- sodiumoxide provider for Ed25519 (#18)
- *ring* Ed25519 provider (#17)
- ed25519::Verifier trait (#16)

## [0.3.2] (2018-03-31)

- Upgrade ed25519-dalek to 0.6.2 (#15)

## [0.3.1] (2018-03-27)

- Update to yubihsm-rs 0.7 (#14)

## [0.3.0] (2018-03-20)

- Refactor providers + `yubihsm-rs` update + `Sync`-safe signers (#13)

## [0.2.0] (2018-03-13)

- Add `ed25519::Signer::public_key()` (#12)

## 0.1.0 (2018-03-12)

- Initial release

[0.10.0]: https://github.com/tendermint/signatory/pull/131
[0.9.4]: https://github.com/tendermint/signatory/pull/126
[0.9.3]: https://github.com/tendermint/signatory/pull/124
[0.9.2]: https://github.com/tendermint/signatory/pull/118
[0.9.1]: https://github.com/tendermint/signatory/pull/116
[0.9.0]: https://github.com/tendermint/signatory/pull/114
[0.8.0]: https://github.com/tendermint/signatory/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/tendermint/signatory/compare/v0.6.1...v0.7.1
[0.6.1]: https://github.com/tendermint/signatory/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/tendermint/signatory/compare/v0.5.2...v0.6.0
[0.5.2]: https://github.com/tendermint/signatory/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/tendermint/signatory/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/tendermint/signatory/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/tendermint/signatory/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/tendermint/signatory/compare/v0.3.2...v0.4.0
[0.3.2]: https://github.com/tendermint/signatory/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/tendermint/signatory/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/tendermint/signatory/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/tendermint/signatory/compare/v0.1.0...v0.2.0

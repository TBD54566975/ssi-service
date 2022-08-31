# SIP Template

**SIP:** 3

**Title:** Signing & Verificaiton

**Author(s):** Gabe Cohen ([@decentralgabe](https://github.com/decentralgabe))

**Comments URI:** 

**Status:** *Draft*

**Created:** *August 31, 2022*

**Updated:** *August 31, 2022*

# Abstract

Support signing and verification in a generic manner for a variety of objects (e.g. Verifiable Credentials, Credential Manifests, Presentation Requests, etc.) to be used in the SSI Service.

## Background

- [W3C Data Integrity](https://w3c.github.io/vc-data-integrity/)
- Signing suites utilizing _Data Integrity_, such as [VC JWS 2020](https://github.com/w3c/vc-jws-2020)
- [Verifiable Credentials Proofs](https://www.w3.org/TR/vc-data-model/#proofs-signatures)
- [Keystore Service PR](https://github.com/TBD54566975/ssi-service/pull/62)

## Goals

**Goals**
- Support a number of key types and signing algorithms, as exposd by the SSI SDK
- Allow integration for signing/verification into other SSI Service modules like `credentials`, in addition to having a standalone API for signing and verifying
	- Support Data Integrity suites, starting with VC JWS 2020
	- Support JW* signing/verification

**Non-goals**
- Encryption/decryption and other cryptographic operations besides signing and verification are not to be covered in this PR

---

# Specification

*Main area for going into your proposal, technical details with diagrams as necessary. It is ok to list multiple possible options, and outline your recommendation.*

---

# Considerations

## Tradeoffs

*What is lost with this approach? What is gained?*

## Failure Modes & Mitigations

*What can go wrong and why? How can it be mitigated?*

## Dependencies

*What dependencies exist between this and other pieces of work?*

## Future Work

*What work comes next/what does this enable?*

## Security & Privacy

*What security and/or privacy implications are relevant to the proposed change?*

---

# Release

## Success Criteria

- A set of unit tests for each component in the new signing / verification code
- An introduction of test in components that make use of signing / verification - such as additional tests for the `credentials` service

## Rollout

- Since the service is pre-versioning, there are no special rollout concerns.

---

# References

* [W3C Data Integrity](https://w3c.github.io/vc-data-integrity/)
* Signing suites utilizing _Data Integrity_, such as [VC JWS 2020](https://github.com/w3c/vc-jws-2020)
* [Verifiable Credentials Proofs](https://www.w3.org/TR/vc-data-model/#proofs-signatures)
* [Keystore Service PR](https://github.com/TBD54566975/ssi-service/pull/62)

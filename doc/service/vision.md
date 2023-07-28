# Vision

The Self Sovereign Identity Service (SSIS) facilitates all things relating to [DIDs](https://www.w3.org/TR/did-core/)
and [Verifiable Credentials](https://www.w3.org/TR/vc-data-model) — in a box! The service is a part of a
larger [Decentralized Web Platform](https://developer.tbd.website/projects/web5) architecture. The SSI Service is a
JSON-API web service that wraps the [ssi-sdk](https://github.com/TBD54566975/ssi-sdk) to facilitate user-focused
interactions on Web5. The service is intended to interact with user interfaces, wallets, decentralized web nodes, and
other web infrastructure.

By taking the lower-level building blocks exposed by the SDK, the service is intended to drastically lower the barrier
to entry for any individual or organization interesting in building on the Web5 stack. Like the SDK, the service is
agnostic to any specific business or use case, and design to be pluggable into external infrastructure whether existing
or new.

# Guiding Principles

The service is assumed to be run by **a single organization** and assumes **external authentication and authorization**.
The service assumes no infrastructure requirements and is flexible to multiple deployment models, databases, key
management solutions, and user interfaces. We expect that a wide array of users and use cases will use and build on top
of the service, creating layers of abstraction and intermediation for processing business logic, handling user accounts,
and so on.

The service may choose to support both synchronous and asynchronous APIs; though generally, it should limit
statefulness. The service may implement a set of “static” APIs that expose functionality like signing or verifying a
credential without relying on the service to create or store the credential itself. Such APIs could expand the utility
of the service and limit re-implementation of foundational SSI functions across application boundaries.

# Feature Support

The future feature set of the SSI is though largely influenced by the standards and features implemented in the SSI SDK,
in aim of advancing the adoption of Self Sovereign Identity. It adheres to best practices and guidelines for
implementing a privacy-minded, secure, and performant service.

We favor evaluating the addition of features and standards on a case-by-case basis, and looking towards implementations
of standards and features that are well-reasoned, with committed developers and use cases. Features that already
demonstrated usage and interoperability outside the project are prime candidates for adoption.

## Language Support

The SSI ecosystem uses a wide set of tools, languages, and technologies: working across web browsers, mobile
applications, backend servers, ledgers, and more. This service
uses [Go](https://go.dev/) because of its robust
cryptographic support, speed, ability to be compiled to [WASM](https://webassembly.org/), and, above all else,
simplicity. It is crucial that the code we write is approachable to encourage contribution. Simple and clear is always
preferred over clever.

The future is multi-language, and multi-platform. We welcome initiatives for improving multi-language and multi-platform
support, and are open to incubating them in our GitHub organization. When future SDKs are developed, it is expected that
they follow the same feature set and API as the Go SDK in addition to fulfilling the suite of language interoperability
tests.
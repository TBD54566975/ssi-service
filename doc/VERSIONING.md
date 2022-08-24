# Versioning

The SSI Service has two types of versioning: Semantic Versioning and URI versioning. Semantic Versioning refers to the
packaging of software on GitHub; whereas URI versioning affects the route path used in accessing the service itself. All
changes are semantically versioned, and versioned changes may include URI version updates.

## Semantic Versioning

For releases, SSI Service follows [Semantic Versioning rules](https://semver.org/) *as much as possible.*

> Given a version number MAJOR.MINOR.PATCH, increment the:
>
> 1. MAJOR version when you make incompatible API changes
> 2. MINOR version when you add functionality in a backwards compatible manner
> 3. PATCH version when you make backwards compatible bug fixes
>
> Additional labels for pre-release and build metadata are available as extensions to the MAJOR.MINOR.PATCH format.
>

Backwards compatible changes are represented by **minor** and **patch** version updates. Breaking API changes result in
a **major** version change.

## URI Versioning

URI versioning is used to version specific APIs. URI versioning uses a simple monotonic incrementing version number (
e.g. `https://ssi-service.com/v1/health`, `https://ssi-service.com/v2/health`, …).

Changes to public APIs should strive to be backwards compatible and avoid version increments. It is possible to *add* *
functionality* to an existing API, and include new APIs without needed to increment its URI version. Breaking changes:
removing or modifying existing public APIs in a non-backwards compatible manner should be avoided, but when necessary,
result in a URI version increment.

---

# Releases

A release is a version-identified distribution of the SSI Service. Releases can be found
on [GitHub’s release page](https://github.com/TBD54566975/ssi-service/releases). Releases are always published via
GitHub, and reference a specific commit hash.

## Release Stability

Releases are classified into three main buckets: alpha, beta, and stable.

### Alpha

Alpha releases may include experimental or incomplete API changes. They are not considered stable and are mostly useful
for developers. Alpha releases may be suffixed with *-alpha*, for example `v0.1.1-alpha`.

### Beta

Beta releases include feature complete API changes that need to gain more confidence. Confidence is gained through
developer and user testing. Beta releases may contain potential bug fixes and patches that need quick adoption. Beta
releases may be suffixed with *-beta*, for example, `v0.2.3-beta`.

### Stable

Stable releases have been well tested and carry the highest level of confidence. They are suited for production-level
usage. They are not suffixed (e.g. `v0.5.2`).

---

## Release Information

1. **Who creates releases?**

The project maintainers are responsible for creates and managing releases. If you are interested in a release but there
isn’t one, consider referencing a specific commit hash (
e.g. `go get github.com/[TBD54566975/ssi-s](https://github.com/TBD54566975/ssi-service@<commit-hash>`) or reaching
out to the team via Discord, the forums, or an issue.

1. **When do we cut a new release?**

Primarily when there are substantive feature changes or when having adoption of a release has some sort of utility —
whether to promote additional testing or to advocate for stability such as in the case of a bug fix.

1. **How are releases represented?**

Releases can be found on [GitHub’s release page](https://github.com/TBD54566975/ssi-service/releases). Release notes
highlighting key changes accompany each release.

1. **Which release should I use?**

It depends on your intended usage. As a general rule you should use the highest numbered version release.

1. **I found a bug for a release, what should I do?**

Open a bug issue, please.
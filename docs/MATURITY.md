# Feature maturity levels

The [README's maturity matrix](../README.md#feature-maturity) gives every
feature one of three levels, the reason for it, and the evidence. This page
defines the levels and the rules for changing one.

| Level | A feature at this level |
|---|---|
| **GA** | is enforced, tested both ways, documented, used in production, and covered by the M1 verification. |
| **Beta** | works and is tested, but is off by default or not externally verified. |
| **Experimental** | is partial, or has no runtime. |

"Tested both ways" means one test shows that the allowed case works and
another shows that the disallowed case is refused
([AI working agreement §3](AI-WORKING-AGREEMENT.md#3-definition-of-done)).

## Rules

- **Nothing is GA until M1 verifies it.** The M1 verification
  ([#954](https://github.com/mhmtgngr/openidx/issues/954)) is:
  - the OpenID Connect conformance suite in CI
    ([#958](https://github.com/mhmtgngr/openidx/issues/958));
  - SAML interop and SCIM compliance tests in CI
    ([#955](https://github.com/mhmtgngr/openidx/issues/955));
  - an independent penetration test
    ([#959](https://github.com/mhmtgngr/openidx/issues/959));
  - the display = enforcement table, automated and recorded for each release
    ([#957](https://github.com/mhmtgngr/openidx/issues/957));
  - operational evidence: a restore, an upgrade, alerts and SLOs
    ([#962](https://github.com/mhmtgngr/openidx/issues/962)).

  None of these has run yet, so no feature is GA today. "GA candidate" marks
  a Beta feature that M1 is meant to verify.
- **Tested means a test in CI exercises what the feature does.** A test of its
  configuration or its storage alone does not count. A feature that does not
  meet every Beta condition is Experimental.
- **When the evidence is unclear, the lower level applies,** and the reason
  says what is missing.
- **A level changes in the pull request that earns it,** with the evidence: a
  test, a document, a recorded run or an issue. A change that removes the
  evidence, or turns a feature off by default, lowers the level in the same
  pull request.
- **The matrix describes `main`,** not a release. It is not a support promise;
  [SUPPORT.md](../SUPPORT.md) says what support there is.

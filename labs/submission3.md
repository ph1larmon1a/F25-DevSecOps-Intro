# Summary: benefits of signing commits
* **Authenticity of authorship:** These tags or commits are marked as verified on GitHub so other people can be confident that the changes come from a trusted source.
* **Integrity of code:** Any tampering after signing is detectable; altered commits fail verification.
* **Accountability & non-repudiation:** Authors can’t plausibly deny changes if the key is controlled and policies are enforced.
* **Provenance for CI/CD:** Build systems can trust only signed inputs, shrinking the attack surface for supply-chain attacks.
* **Policy enforcement:** Branch protections and server hooks can reject unsigned or unverified commits/merges.
* **Compliance support:** Helps meet SSDF/SLSA-style controls around source integrity and traceability.
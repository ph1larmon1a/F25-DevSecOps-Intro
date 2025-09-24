# Summary: benefits of signing commits

* **Authenticity of authorship:** These tags or commits are marked as verified on GitHub so other people can be confident that the changes come from a trusted source.
* **Integrity of code:** Any tampering after signing is detectable; altered commits fail verification.
* **Accountability & non-repudiation:** Authors can’t plausibly deny changes if the key is controlled and policies are enforced.
* **Provenance for CI/CD:** Build systems can trust only signed inputs, shrinking the attack surface for supply-chain attacks.
* **Policy enforcement:** Branch protections and server hooks can reject unsigned or unverified commits/merges.
* **Compliance support:** Helps meet SSDF/SLSA-style controls around source integrity and traceability.

# Evidence of successful SSH key setup & configuration

```
git config --global --get gpg.format          # -> ssh
git config --global --get user.signingkey     # -> ~/.ssh/id_ed25519.pub
git config --global --get commit.gpgsign      # -> true
```

# Analysis: Why commit signing is critical in DevSecOps workflows

1) It defends your first trust boundary.
DevSecOps automates everything—scanners, tests, builds, deploys. That means the source commit is the earliest control point. If you don’t verify commit provenance, a stolen credential or malicious actor can smuggle code that every automated step will happily build and ship.

2) Tamper-evidence from developer laptop -> production.
Signatures travel with commits. If a repo, cache, or artifact store is compromised, signature checks will fail, stopping the pipeline before bad code becomes a bad release.

3) Enforceable, machine-checkable policy.
You can make “only signed commits/merges allowed” a hard gate: branch protections, pre-receive hooks, and CI jobs (git verify-commit) can block unsigned or untrusted keys. This converts a human process into a technical control.

4) Supports compliance & forensics.
Signed history provides non-repudiation and traceability for audits (SSDF, SLSA, ISO 27001). Post-incident, you can rapidly scope which commits are trustworthy.

5) Fits modern, cloud-native supply chains.
Combine signed commits with signed tags/releases and artifact signing (e.g., container images). Your pipeline asserts integrity end-to-end, from Git to registry to runtime admission.

# Screenshots or verification of the "Verified" badge on GitHub
![alt text](IMG_3066.jpeg)
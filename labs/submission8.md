# Lab 8 - Software Supply Chain Security: Signing, Verification, and Attestations

## Task 1 - Local Registry, Signing & Verification

### How signing protects against tag tampering

Docker **tags are mutable** pointers. Anyone with push access (or a compromised credential) can retag a different image under the same tag (e.g., `juice-shop:v19.0.0`). By contrast, a **digest** (e.g., `sha256:872e…`) identifies the exact image manifest immutably.

**Cosign** signs the **digest**, not the tag. The signature binds:
- **public key identity** (from `cosign.pub`),
- to the **subject digest** (the image’s immutable content hash),
- plus some metadata (time, optional annotations).

During verification, Cosign fetches the signature object from the registry and checks that:
1. It’s **cryptographically valid** against public key.
2. The **digest you are verifying** is the same digest that was originally signed (the *subject digest* in the signature).

Therefore, if someone re-points the **tag** to a different image (tag tampering), the **digest changes**, and verification **fails** for that new digest. This prevents an attacker from silently swapping image contents under a trusted tag: the signature no longer matches.

---

### What “subject digest” means

In Sigstore/Cosign terminology, the **subject** of a signature is *what is being signed*. For container images, the **subject is the image manifest’s digest** (e.g., `sha256:...`). This hash is computed over the image manifest (which references layer digests), making it a content-addressed, immutable identifier.

- **Subject digest** = the immutable identifier of the artifact that the signature attests to.
- When `cosign verify` runs, it compares the digest you requested to verify with the **subject digest recorded inside the signature**. If they differ, verification fails.

---

## Task 2 - Attestations: SBOM (reuse) & Provenance

### How attestations differ from signatures

- **Signature**: proves *authenticity/integrity* of the **image digest**. It answers: *“Did this exact artifact (subject digest) come from the holder of this key?”*
- **Attestation**: a signed **statement _about_ an artifact** (still bound to the same subject digest) with a specific **predicate type** (e.g., CycloneDX SBOM, SLSA provenance). It answers: *“What facts/metadata can the signer assert about this artifact?”* Attestations travel as OCI objects alongside the image and are verified with `cosign verify-attestation`.

In short: a plain signature says **“trust this digest”**; an attestation says **“here is verifiable evidence _about_ this digest.”**

### What the SBOM attestation contains (CycloneDX)

SBOM attestation (`--type cyclonedx` with `--predicate labs/lab8/attest/juice-shop.cdx.json`) typically includes:
- **Components**: packages/libraries present in the image (names, versions, package URLs).
- **Hashes** for component integrity (where available).
- **Licenses** and **supplier** metadata.
- **Dependencies/relationships** between components.
- Optional **vulnerability** references or external references (depends on generator/content).
Because it’s an **attestation**, this document is cryptographically bound to the **image’s subject digest**, preventing mix‑and‑match with a different image.

### What provenance attestations provide (SLSA)

minimal SLSA v1 predicate (`--type slsaprovenance`) conveys **how** the image was produced:
- **builder.id**: who/what built it (here: `student@local`).
- **buildType**: process kind (here: `manual-local-demo`).
- **invocation.parameters**: inputs (here: the `image` value referencing the immutable digest).
- **metadata.buildStartedOn** (RFC3339) and **completeness** flags.

These fields let consumers reason about **build integrity** and **reproducibility**, form policy (e.g., “only accept images built by CI X with buildType Y”), and trace back to sources. In stronger setups, provenance links to version control, build steps, materials, and attest Rekor inclusion.

### Attestation envelope: decoded example

From `verify-provenance.txt`, the `payloadType` is `application/vnd.in-toto+json`. Decoding the `payload` yields an in‑toto Statement whose `predicateType` is SLSA provenance v0.2 and whose **subject** carries the image digest.

Saved decoded JSON:
- `/labs/lab8/attest/verify-provenance-decoded.json`

Excerpt (trimmed):
```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "subject": [
    {
      "name": "localhost:5001/juice-shop",
      "digest": { "sha256": "872efcc03cc16e8c4e2377202117a218be83aa1d05eb22297b248a325b400bd7" }
    }
  ],
  "predicate": {
    "builder": { "id": "student@local" },
    "buildType": "manual-local-demo",
    "invocation": {
      "parameters": {
        "image": "localhost:5001/juice-shop@sha256:872efcc03cc16e8c4e2377202117a218be83aa1d05eb22297b248a325b400bd7"
      }
    },
    "metadata": {
      "buildStartedOn": "2025-10-31T17:21:46Z",
      "completeness": { "parameters": true }
    }
  }
}
```

This shows the **subject digest** binding and the provenance facts that were attested.

---

## Task 3 - Artifact (Blob/Tarball) Signing

### Why sign non‑container artifacts?

Common use cases include:
- **Release binaries & installers** (Linux/macOS/Windows builds, CLI tools).
- **Infrastructure as Code** (Helm charts, Terraform modules, Kustomize bases).
- **Configuration & policy** (YAMLs, OPA/Conftest bundles, admission policies).
- **SBOMs, provenance, advisories** (documents that describe or govern artifacts).
- **Scripts & templates** (bootstrap scripts, migration SQL, Ansible roles).
- **ML/AI & WebAssembly** (models, datasets, `.wasm` modules).
- **Firmware & appliances** (router images, device packages).

Signing lets consumers verify **authenticity** (came from the expected signer) and **integrity** (bytes unchanged), even when artifacts are distributed via mirrors, Git releases, or direct downloads.

### How blob signing differs from container image signing

| Aspect | Container image signing | Blob (file/tarball) signing |
|---|---|---|
| **What’s signed** | The **image manifest digest** (subject digest) | The **exact bytes of the file** |
| **Where signature lives** | Stored in the **OCI registry** next to the image (as an OCI artifact) | Stored as a **detached file** (e.g., `.sig`, **bundle**), can be shipped anywhere |
| **Reference used** | **Immutable digest reference** `repo@sha256:...` | **File path / bytes**; no registry reference involved |
| **Verification lookup** | Cosign pulls signature from the registry for that digest | Cosign reads the local **signature/bundle** and checks it against the file bytes |
| **Transparency log (Rekor)** | Typically enabled in production | Optional; when using a **bundle** with Rekor, inclusion proof travels with the artifact |

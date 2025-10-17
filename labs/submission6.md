# Lab 6 - Infrastructure-as-Code Security: Scanning & Policy Enforcement

## Task 1 - Terraform & Pulumi Security Scanning

### Terraform Tool Comparison - tfsec vs. Checkov vs. Terrascan

#### Coverage & Rule Depth

* **Checkov (78)** surfaced the most failed checks, indicating **broad coverage** and many cloud/provider-specific policies. It also includes Kubernetes, Dockerfile, and CI policies when enabled, but we limited to Terraform.
* **tfsec (53)** produced a **balanced** set of issues with clear remediation guidance. Its rules focus tightly on Terraform semantics and common cloud misconfigs.
* **Terrascan (22)** reported **fewer but higher-signal** violations. Terrascan often emphasizes policy-as-code (OPA/Rego) style governance and can be stricter about certain baselines.

#### Signal-to-Noise & Duplicates

* **Checkov** may flag multiple checks for the same resource (e.g., encryption-at-rest + KMS key requirements), which increases counts but can feel noisy without suppression baselines.
* **tfsec** tends to consolidate related findings with helpful context and links, making triage faster for small repos.
* **Terrascan** produced the fewest alerts, which helped focus, but it can miss some niche provider rules that Checkov covers.

#### Developer Experience (DX)

* **tfsec:** Simple CLI, succinct output, good human-readable report.
* **Checkov:** Rich output formats, strong CI integration, easy skip/justification annotations.
* **Terrascan:** Strong policy model and good JSON for pipelines; human-readable output is adequate.

> **Conclusion:** For breadth and guardrails, **Checkov** led this repo. For actionable triage, **tfsec** struck a good balance. **Terrascan** offered concise, policy-centric results.

---

### Pulumi Security Analysis - KICS Results

**Totals:** 6 findings • **HIGH:** 2 • **MEDIUM:** 2 • **LOW:** 0
KICS supports Pulumi by statically analyzing Pulumi YAML/state-like manifests and applying cloud-specific queries.

#### Observations

* Findings concentrated in **baseline cloud hardening** (e.g., encryption-at-rest, overly permissive network access) and **identity/resource exposure** checks.
* The lower count compared to Terraform likely reflects both **smaller Pulumi surface area** in this repo and **differences in how resources are expressed**.
* KICS’s Pulumi queries mapped well to common AWS/Azure/GCP misconfig classes; results were easy to export as JSON/HTML and summarize for stakeholders.

---

### Terraform vs. Pulumi - Security Themes

| Dimension                | Terraform (HCL)                                                                                      | Pulumi (YAML / programmatic)                                                                               |
| ------------------------ | ---------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| **Expression style**     | Declarative HCL; resources + modules                                                                 | Programmatic configuration rendered to YAML/manifests                                                      |
| **Static analyzability** | Very high; mature scanners and rule catalogs                                                         | Improving; KICS covers many core cloud queries                                                             |
| **Typical misconfigs**   | Publicly exposed services, missing encryption/KMS, permissive IAM, open SGs, insecure S3/Blob config | Similar classes, plus risks from **conditional/resource generation logic** if defaults aren’t securely set |
| **Triage ergonomics**    | Lots of tooling & IDE integration                                                                    | Good with KICS export; fewer overlapping tools today                                                       |

> **Takeaway:** Both styles can be secured effectively. Terraform benefits from a **denser tooling ecosystem**; Pulumi requires ensuring **secure defaults** in code paths and validating generated manifests.

---

### KICS Pulumi Support - Evaluation

* **Strengths**

  * Native support for Pulumi manifests with **Pulumi-specific queries** across AWS/Azure/GCP/Kubernetes.
  * Multiple report formats (JSON/HTML/console) simplify **CI publishing** and stakeholder reporting.
  * Clear severity counters (HIGH/MEDIUM/LOW) aid SLA-based remediation.
* **Gaps/Considerations**

  * Complex, code-driven Pulumi projects may generate resources dynamically; static analysis may miss **runtime-conditioned** paths.
  * Fewer alternative Pulumi-focused scanners available, so **defense-in-depth** relies on KICS + cloud-native checks (e.g., CSPM, IaC tests in CI).

---

### Critical Findings (Top 5+ Themes)

1. **Unencrypted data at rest** (storage buckets/volumes without encryption or without customer-managed keys).
2. **Overly permissive network access** (security groups/firewall rules allowing `0.0.0.0/0` to sensitive ports).
3. **Public object storage** (anonymous read/list on buckets or missing block-public-access controls).
4. **IAM privilege escalation risks** (wildcard `*` actions/resources, broad roles, missing condition keys).
5. **Missing TLS or weak policies** (HTTP endpoints without redirect/HSTS; load balancers/listeners lacking TLS enforcement).
6. **Logging/monitoring gaps** (disabled access logs, missing flow logs, no audit trails/KMS for logs).

---

### Tool Strengths - What Each Excels At

* **tfsec**

  * Terraform-native checks with concise guidance; great for **dev PR checks**.
  * Good balance of breadth vs. noise; easy to adopt locally.
* **Checkov**

  * **Broadest policy catalog**; deep provider/Kubernetes coverage.
  * Strong **baseline/skip management** and CI annotations; ideal for **org-wide guardrails**.
* **Terrascan**

  * **Policy-as-code** orientation; integrates with OPA/Rego mental models.
  * Concise results suitable for **gatekeeping** stages in pipelines.
* **KICS (Pulumi)**

  * First-class Pulumi support and **clear severities**; HTML reports are stakeholder-friendly.
  * Useful as the **primary static scanner** for Pulumi until more tools mature.

---

## Task 2 - Ansible Security Scanning with KICS

**Totals:** 9 findings • **HIGH:** 8 • **MEDIUM:** 0 • **LOW:** 1

### Ansible Security Issues (Key Problems)

Based on KICS output for the vulnerable playbooks, the most critical issue classes were:

1. **Use of `shell`/`command` without hardening** (e.g., no `creates`/`removes`, no input sanitization) → risk of command injection and non-idempotence.
2. **World-writable file permissions** set via `file` or `copy` modules (e.g., `mode: 0777`) → privilege escalation and lateral movement.
3. **Unpinned packages/versions** in `apt`/`yum`/`pip` tasks → supply-chain drift and unexpected vulnerable versions.
4. **Service misconfiguration** (e.g., starting services without enabling secure configs or TLS) → exposure of insecure daemons.
5. **Plaintext secrets** embedded in vars/templates → secrets disclosure in repos, CI logs, or artifact stores.

### Best Practice Violations (Examples & Impact)

* **Running ad-hoc shell commands** instead of purpose-built modules (Impact: injection risk, brittle idempotence).
* **Missing `become: false` on non-privileged tasks** or overuse of privilege escalation (Impact: expands blast radius of playbooks).
* **Lax file modes** like `0644` for private keys or config with credentials (Impact: unauthorized read/access by other users).

### KICS Ansible Queries — What It Checks

KICS evaluates Ansible against checks such as:

* Insecure permissions and ownership on files/directories.
* Use of high-risk modules or patterns (e.g., raw `shell` without guards, unvalidated inputs).
* Package/source hygiene (e.g., unpinned versions, insecure transports, missing GPG verification in some contexts).
* Service/network exposure (e.g., enabling services without secure configuration or firewalling).
* Secret handling in variables/templates.

### Remediation Steps (Targeted)

1. **Prefer safe modules** (`user`, `package`, `systemd`, `ufw`, `iptables`) over `shell`/`command`. If shell is required, add idempotent guards (`creates`, `removes`, `unless`, `onlyif`).
2. **Harden permissions**: set minimal modes (e.g., `0600` for secrets, `0640` for configs), validate with `stat` tasks.
3. **Pin versions** and verify sources; use repository keys and checksums; document update cadence.
4. **Principle of least privilege**: add `become: false` by default, scope `become: true` only where necessary; avoid global privilege escalation.
5. **Secrets management**: move secrets to **Ansible Vault**, environment variables, or external secret stores; never commit plaintext secrets.
6. **Secure services**: template configs with TLS, auth, and logging; ensure firewall rules restrict exposure.

---

## Task 3 - Comparative Tool Analysis & Security Insights

### Tool Comparison Matrix

| Criterion             | tfsec                          | Checkov                         | Terrascan               | KICS                                              |
| --------------------- | ------------------------------ | ------------------------------- | ----------------------- | ------------------------------------------------- |
| **Total Findings**    | 53                             | 78                              | 22                      | 6 (Pulumi) + 9 (Ansible)                          |
| **Scan Speed**        | Fast                           | Medium                          | Medium                  | Fast                                              |
| **False Positives**   | Low–Medium                     | Medium–High                     | Low–Medium              | Medium                                            |
| **Report Quality**    | ⭐⭐⭐                            | ⭐⭐⭐⭐                            | ⭐⭐                      | ⭐⭐⭐ (JSON/HTML)                                   |
| **Ease of Use**       | ⭐⭐⭐⭐                           | ⭐⭐⭐                             | ⭐⭐⭐                     | ⭐⭐⭐                                               |
| **Documentation**     | ⭐⭐⭐                            | ⭐⭐⭐⭐                            | ⭐⭐⭐                     | ⭐⭐⭐                                               |
| **Platform Support**  | Terraform                      | Multiple (Terraform, K8s, etc.) | Multiple                | Multiple (Ansible, Terraform*, K8s, Docker, etc.) |
| **Output Formats**    | JSON, text, SARIF              | JSON, SARIF, JUnit, CLI         | JSON, human             | JSON, HTML, CLI                                   |
| **CI/CD Integration** | Easy                           | Easy                            | Medium                  | Easy                                              |
| **Unique Strengths**  | Dev-friendly, concise guidance | Broadest rules & guardrails     | Policy/governance focus | First-class Ansible & Pulumi coverage             |

*KICS also scans Terraform but wasn’t used for Terraform in this lab.

### Vulnerability Category Analysis

| Security Category             | tfsec      | Checkov         | Terrascan | KICS (Pulumi) | KICS (Ansible) | **Best Tool**           |
| ----------------------------- | ---------- | --------------- | --------- | ------------- | -------------- | ----------------------- |
| **Encryption Issues**         | Strong     | **Very strong** | Moderate  | Strong        | N/A            | **Checkov**             |
| **Network Security**          | **Strong** | Strong          | Moderate  | Moderate      | Moderate       | **tfsec / Checkov**     |
| **Secrets Management**        | Moderate   | **Strong**      | Basic     | Strong        | **Strong**     | **Checkov / KICS**      |
| **IAM/Permissions**           | Strong     | **Very strong** | Moderate  | Moderate      | Moderate       | **Checkov**             |
| **Access Control**            | Strong     | **Strong**      | Moderate  | Moderate      | Strong         | **Checkov / tfsec**     |
| **Compliance/Best Practices** | Moderate   | **Very strong** | Strong    | Moderate      | Strong         | **Checkov / Terrascan** |

**Notes:**

* Checkov consistently excels in breadth (encryption, IAM, compliance).
* tfsec surfaces clear network/storage misconfigs with high signal.
* Terrascan is strongest when aligned to policy-as-code governance.
* KICS shines for **Ansible** and **Pulumi** where alternatives are limited.

### Top 5 Critical Findings (Deep Dive + Fixes)

Below are representative issues observed across tools with **remediation snippets**.

1. **Open Security Group (0.0.0.0/0) to SSH**
   Terraform (HCL):

```hcl
resource "aws_security_group_rule" "ssh_restricted" {
  type              = "ingress"
  security_group_id = aws_security_group.web.id
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["203.0.113.0/24"] # restrict to office/VPN
}
```

Ansible:

```yaml
- name: Restrict SSH via UFW
  community.general.ufw:
    rule: allow
    port: "22"
    proto: tcp
    src: 203.0.113.0/24
```

Pulumi (YAML - AWS example):

```yaml
resources:
  sshRule:
    type: aws:ec2/SecurityGroupRule
    properties:
      type: ingress
      securityGroupId: ${web.id}
      fromPort: 22
      toPort: 22
      protocol: tcp
      cidrBlocks:
        - 203.0.113.0/24
```

2. **Public Object Storage / Missing Public Access Block**
   Terraform:

```hcl
resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

Pulumi (YAML):

```yaml
resources:
  pab:
    type: aws:s3/BucketPublicAccessBlock
    properties:
      bucket: ${logs.id}
      blockPublicAcls: true
      blockPublicPolicy: true
      ignorePublicAcls: true
      restrictPublicBuckets: true
```

3. **Unencrypted Volumes/Datastores**
   Terraform:

```hcl
resource "aws_ebs_volume" "db" {
  availability_zone = var.az
  size              = 100
  encrypted         = true
  kms_key_id        = aws_kms_key.ebs.arn
}
```

Pulumi (YAML):

```yaml
resources:
  dbVolume:
    type: aws:ec2/Volume
    properties:
      availabilityZone: ${az}
      size: 100
      encrypted: true
      kmsKeyId: ${kms.arn}
```

4. **IAM Wildcards (`Action: "*"`, `Resource: "*"`)**
   Terraform:

```hcl
data "aws_iam_policy_document" "scoped" {
  statement {
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["arn:aws:s3:::my-bucket/*"]
    effect    = "Allow"
    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
  }
}
```

Ansible (community.aws.iam_policy):

```yaml
- name: Attach scoped IAM policy
  community.aws.iam_policy:
    iam_type: user
    iam_name: ci-user
    state: present
    policy_document: "{{ lookup('file', 'policy.json') }}"
```

5. **Plaintext Secrets in Code**
   Terraform (use sensitive inputs/Secrets Manager):

```hcl
variable "db_password" { type = string; sensitive = true }

resource "aws_secretsmanager_secret" "db" { name = "db/password" }
resource "aws_secretsmanager_secret_version" "dbv" {
  secret_id     = aws_secretsmanager_secret.db.id
  secret_string = var.db_password
}
```

Pulumi (use config as secret):

```yaml
config:
  myapp:dbPassword:
    secure: true
```

Ansible (Vault):

```bash
ansible-vault create group_vars/prod/vault.yml
# then reference with !vault variables in tasks/templates
```

### Tool Selection Guide

* **Developer PR checks (fast feedback):** use **tfsec** (and/or Checkov) with SARIF annotations.
* **Org-wide guardrails & compliance:** **Checkov** as the primary gate with policy baselines.
* **Governance/policy-as-code:** **Terrascan** for curated Rego policies and centralized enforcement.
* **Pulumi & Ansible projects:** **KICS** as the main static scanner; complement with platform-specific linters (e.g., `ansible-lint`).

### Lessons Learned

* **Breadth vs. signal:** Checkov found the most issues; tfsec’s findings were easier to triage quickly.
* **Context matters:** Counts vary due to rule overlap and deduping; always normalize against severity and asset criticality.
* **Defense in depth:** No single tool covers everything (especially outside Terraform); combine scanners.

### CI/CD Integration Strategy (Practical)

1. **Matrix job** over `terraform`, `pulumi`, `ansible` paths.
2. **Run scanners in parallel**: tfsec, Checkov, Terrascan, KICS.
3. **Fail gates**: fail build on any **HIGH**; warn on **MEDIUM**; publish artifacts always.
4. **Publish reports**: upload JSON/HTML; convert to **SARIF** for PR annotations (GitHub code scanning).
5. **Baselines**: commit baseline files/skip annotations with justification; review quarterly.
6. **Scheduled scans**: nightly on `main` to catch drift.

### Justification

This strategy pairs **coverage** (Checkov), **signal & dev UX** (tfsec), **governance** (Terrascan), and **ecosystem reach** (KICS) to minimize risk across heterogeneous IaC codebases.

---
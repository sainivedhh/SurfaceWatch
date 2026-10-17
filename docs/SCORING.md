# SurfaceWatch Finding Severity & Risk Scoring Model

## 1. Overview
SurfaceWatch employs a deterministic, transparent risk scoring engine that normalizes vulnerabilities and attack-surface exposures onto a continuous **0.0 to 100.0 scale**, mapping directly to industry standard severity tiers (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).

---

## 2. Mathematical Formula

$$\text{Score} = \min\left(100.0, \; \text{TypeWeight} \times \text{ExposureFactor} \times \text{Confidence} \times 10.0\right)$$

Where:
1. **TypeWeight** ($1.0 \le W \le 10.0$): Intrinsic hazard and exploitability of the finding class.
2. **ExposureFactor** ($0.5 \le E \le 1.0$): Visibility and accessibility of the asset hosting the issue.
3. **Confidence** ($0.5 \le C \le 1.0$): Verifiability of the signal (structural regex / signed TLS vs heuristic anomaly).

---

## 3. Factor Coefficients

### 3.1 Type Weights ($\text{TypeWeight}$)
| Finding Type | Type Weight | Description |
| :--- | :--- | :--- |
| `exposed_aws_key` | **10.0** | Direct cloud infrastructure compromise |
| `exposed_github_token` | **10.0** | Source code and CI/CD takeover |
| `exposed_private_key` | **10.0** | Asymmetric cryptographic identity theft |
| `dangling_cname_takeover` | **9.0** | Domain hijacking on third-party SaaS/Cloud |
| `exposed_db_credential` | **9.0** | Direct database read/write access |
| `expired_tls_certificate` | **7.5** | Immediate visitor trust degradation & MITM risk |
| `weak_tls_version` | **7.0** | Protocol downgrade (TLS 1.0/1.1) |
| `active_typosquat_domain` | **6.0** | Brand impersonation and phishing active |
| `expiring_tls_certificate` | **5.0** | Cert expiring within 30 days |
| `self_signed_certificate` | **5.0** | Untrusted root CA |
| `missing_hsts_header` | **4.5** | Potential SSL stripping |
| `high_entropy_secret` | **4.0** | Unclassified cryptographic key candidate |
| `missing_csp_header` | **3.0** | XSS defense-in-depth absence |
| `missing_x_content_type_options`| **2.5** | MIME sniffing vulnerability |
| `missing_x_frame_options` | **2.5** | Clickjacking vulnerability |
| `discovered_subdomain` | **1.0** | Informational reconnaissance |
| `dns_resolution` | **1.0** | Informational network baseline |

### 3.2 Exposure Factor ($\text{ExposureFactor}$)
- **Root Domain** (`domain`): `1.0` (Directly reachable by the global internet).
- **Subdomain** (`subdomain`): `0.95` (Accessible externally, scoped application surface).
- **CIDR Block** (`cidr`): `0.90` (Network range).
- **Repository** (`repo`): `0.85` (Internal or authorized source directory).

### 3.3 Confidence ($\text{Confidence}$)
- **Direct Match**: `1.0` (Exact regex, structured token, validated checksum, TLS handshake).
- **Heuristic Anomaly**: `0.85` (Shannon entropy statistical deviation, permutation engine).

---

## 4. Severity Tier Thresholds

| Score Range | Severity Tier | Action Required |
| :--- | :--- | :--- |
| **80.0 – 100.0** | `CRITICAL` | Immediate emergency response (key revocation, incident triage) |
| **60.0 – 79.9** | `HIGH` | Remediate within 24 hours (fix orphan DNS, rotate passwords) |
| **35.0 – 59.9** | `MEDIUM` | Scheduled remediation within current sprint (cert renewal, HSTS) |
| **15.0 – 34.9** | `LOW` | Best-practice hardening (CSP, security headers) |
| **0.0 – 14.9** | `INFO` | Attack-surface inventory and telemetry |

---

## 5. Worked Examples

### Example 1: Exposed AWS Access Key in Repo
- **Type**: `exposed_aws_key` ($\text{Weight} = 10.0$)
- **Asset**: Repo directory ($\text{Exposure} = 0.85$)
- **Confidence**: Structured `AKIA...` regex ($\text{Confidence} = 1.0$)
- **Calculation**: $10.0 \times 0.85 \times 1.0 \times 10.0 = \mathbf{85.0}$
- **Result**: `CRITICAL` (Immediate rotation)

### Example 2: Dangling CNAME Takeover on Subdomain
- **Type**: `dangling_cname_takeover` ($\text{Weight} = 9.0$)
- **Asset**: Subdomain `blog.example.com` ($\text{Exposure} = 0.95$)
- **Confidence**: Direct NXDOMAIN resolution ($\text{Confidence} = 1.0$)
- **Calculation**: $9.0 \times 0.95 \times 1.0 \times 10.0 = \mathbf{85.5}$
- **Result**: `CRITICAL`

### Example 3: Active Typosquat Domain
- **Type**: `active_typosquat_domain` ($\text{Weight} = 6.0$)
- **Asset**: Root Domain `example.com` ($\text{Exposure} = 1.0$)
- **Confidence**: Permutation resolution heuristic ($\text{Confidence} = 0.85$)
- **Calculation**: $6.0 \times 1.0 \times 0.85 \times 10.0 = \mathbf{51.0}$
- **Result**: `MEDIUM`

### Example 4: Missing Content-Security-Policy (CSP)
- **Type**: `missing_csp_header` ($\text{Weight} = 3.0$)
- **Asset**: Subdomain ($\text{Exposure} = 0.95$)
- **Confidence**: Direct HTTP response header check ($\text{Confidence} = 1.0$)
- **Calculation**: $3.0 \times 0.95 \times 1.0 \times 10.0 = \mathbf{28.5}$
- **Result**: `LOW`

# SurfaceWatch Security & Threat Model

## 1. Authorized-Use Policy (Non-Negotiable)

SurfaceWatch is built strictly for authorized monitoring of digital assets, domains, and repositories owned and operated by the deploying entity. 

- **Scope Allowlist Enforcement**: No collector is permitted to communicate with or evaluate any target outside the operator's explicitly listed scope in `scope.yaml`.
- **Passive Operations Only**: SurfaceWatch does not perform port scans, TCP SYN floods, vulnerability fuzzing, crawling, or exploitation. All network actions are strictly passive: Certificate Transparency public log queries, standard DNS record resolution, public TLS metadata inspection, and HTTP response header checks.
- **Credential Safety**: Raw exposed credentials (such as AWS keys, database passwords, or GitHub tokens) are **never written to disk or database tables**. Only a safe redacted preview (e.g. `AKIA...REDACTED...W3QA`) and a salted SHA-256 hash are retained.

---

## 2. Threat Model

### 2.1 Threat Actors & Vectors
1. **Malicious Tenant / Insider**:
   - *Threat*: Tenant attempts to access finding data belonging to another tenant (Insecure Direct Object Reference - IDOR).
   - *Mitigation*: All queries in `FindingStore`, `AssetStore`, and `ScanStore` strictly filter by `tenant_id` extracted from the cryptographically validated API key context.
2. **Server-Side Request Forgery (SSRF) / DNS Rebinding**:
   - *Threat*: Attacker registers an outbound webhook pointing to cloud metadata services (`169.254.169.254`) or internal microservices (`10.0.0.1`, `127.0.0.1`), using DNS rebinding to bypass static URL filters.
   - *Mitigation*: Outbound HTTP client executes connect-time DNS validation (`SafeDialContext`), pins the TCP connection to the validated public IP, and rejects private/loopback/link-local CIDRs immediately.
3. **Denial of Service via Request Inflation**:
   - *Threat*: Attacker sends deeply nested or multi-megabyte payloads to exhaust memory.
   - *Mitigation*: `MaxBodySize` middleware enforces a strict 1MB cap via `http.MaxBytesReader` before decoding JSON.
4. **Target Infrastructure Degradation**:
   - *Threat*: Scanner hammers target domains, triggering downtime or false incident alerts.
   - *Mitigation*: Per-host token bucket rate limiting throttles requests to configured limits (default 5 req/sec).

---

## 3. Authentication & RBAC Design

### API Key Structure
- Keys are transmitted via `X-API-Key: <token>` or `Authorization: Bearer <token>`.
- Raw tokens are stored as **Bcrypt hashes** with default cost factor. Lookups use constant-time comparison to prevent timing attacks.

### Role Hierarchy
| Role | Level | Permitted Operations |
| :--- | :--- | :--- |
| **Viewer** | 1 | `GET /api/v1/assets`, `GET /api/v1/scans`, `GET /api/v1/findings`, `GET /api/v1/stats/summary` |
| **Analyst**| 2 | All Viewer permissions + `POST /api/v1/scans`, `PATCH /api/v1/findings/{id}/status` |
| **Admin**  | 3 | All Analyst permissions + `POST /api/v1/assets`, Webhook configuration, Scope updates |

---

## 4. Defense-in-Depth HTTP Headers

Every API response automatically includes security headers to mitigate browser-side attacks:
- `X-Content-Type-Options: nosniff`: Prevents MIME confusion attacks.
- `X-Frame-Options: DENY`: Prevents UI redressing and clickjacking.
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`: Enforces HTTPS.
- `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`: Restricts script and frame execution.
- `Referrer-Policy: no-referrer`: Prevents token and path leakage in Referer headers.
- `X-XSS-Protection: 1; mode=block`: Legacy browser cross-site scripting filter.

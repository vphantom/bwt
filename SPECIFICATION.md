# Binary Web Token Specification

**Status:** Draft — 2026-05-26

## 1. Overview

Binary Web Tokens (BWT) provide near-stateless authentication tokens compact enough for HTTP cookies and e-mail links.  Unlike JWT, BWT requires minimal server-side state (a per-user logout timestamp) to guarantee timely revocation.

BWT defines three token forms:

| Form    | Purpose                          | Signature | Salt sep | Payload fields                   |
| ------- | -------------------------------- | --------- | -------- | -------------------------------- |
| Session | HTTP session cookies             | 224 bits  | `:`      | issued_at, expires, user, admin? |
| Link    | One-time URLs (email, password)  | 128 bits  | `=`      | issued_at, expires, user         |
| CSRF    | Cross-site request forgery guard | 96 bits   | `~`      | rand                             |

**What BWT is not:** BWT does not provide confidentiality, request authorization, form integrity, clickjacking protection, or replay protection for session cookies.  Applications must implement their own controls for these concerns.

## 2. Common Elements

### 2.1 Safe-Hex Encoding

Standard hexadecimal and common base-32/64 encodings risk false positives from profanity filters in e-mailed URLs.  BWT uses an alternative hexadecimal alphabet with no vowels or vowel-lookalikes:

| Hex      | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | A | B | C | D | E | F |
| -------- | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - |
| Safe-Hex | G | H | J | K | L | M | N | P | Q | R | S | T | V | W | X | Z |

Only these 16 uppercase characters (`GHJKLMNPQRSTVWXZ`) are valid.  There is zero overlap with standard hex digits (`0-9A-F`), making accidental confusion impossible.

Integers are encoded as left-trimmed safe-hex strings: no leading `G` characters except for the value zero itself, which encodes as `G`.

### 2.2 Token Format

All tokens are ASCII strings composed of two sections separated by `9`:

```
<payload>9<signature>
```

- **Payload** — One or more safe-hex encoded unsigned integers, delimited by `5`.
- **Signature** — Safe-hex encoded HMAC-SHA-224 output (possibly truncated; length depends on form).

Trailing `5` delimiters in the payload must be trimmed.  For example, if the last field is optional and absent, the payload must not end with `5`.

### 2.3 Timestamps

Timestamps in BWT payloads are seconds since a BWT-specific epoch: **UNIX Epoch + 1,750,750,750 seconds** (approximately 2025-06-24).  This offset keeps encoded values smaller.

When a token field says `issued_at`, it stores `unix_timestamp - 1_750_750_750`.

The `expires` field stores a duration in minutes (range: 1–1440).

A token has not expired when: `now < issued_at + 1_750_750_750 + expires × 60`.

A token is not from the future when: `issued_at + 1_750_750_750 ≤ now + 5` (5-second skew allowance).

### 2.4 Key Management

Servers maintain two HMAC keys:

- **today** — The current day's key.
- **yesterday** — The previous day's key.

Keys are rotated daily in a consistent time zone (typically UTC).  Both keys are accepted during signature verification, ensuring tokens remain valid across the rotation boundary.

Keys must be between **64 and 128 bytes** in length and generated from a cryptographically secure random source.

### 2.5 HMAC Signing

Signatures are computed using HMAC-SHA-224 over the string:

```
salt <sep> payload
```

Where:

- `salt` is a context-specific string (may be empty).
- `<sep>` is a single ASCII character that depends on the token form (see §3–5).
- `payload` is the final encoded payload (safe-hex values and `5` delimiters, as they appear in the token).

The full 224-bit HMAC output is safe-hex encoded.  Depending on the form, this encoded signature is used in full or truncated to a prefix.

Truncation security: truncating HMAC-SHA-224 to 128 or 96 bits is acceptable per RFC 2104 §5 (output ≥ half the hash length, ≥ 80 bits) and NIST SP 800-107 Rev. 1 §5.3.4.

### 2.6 Signature Verification

Implementations must use **constant-time comparison** when verifying signatures.  The token's signature is checked against today's key first; if that fails and a yesterday key is available, it is checked against yesterday's key.

## 3. Session Tokens

Session tokens are designed for HTTP cookies.  They carry the full 224-bit signature.

### 3.1 Format

| Property          | Value     |
| ----------------- | --------- |
| Salt separator    | `:`       |
| Signature bits    | 224       |
| Signature chars   | 56        |
| Max token length  | 124 bytes |

### 3.2 Payload Fields

| # | Field     | Required | Description                 |
| - | --------- | -------- | --------------------------- |
| 1 | issued_at | yes      | Seconds since BWT epoch     |
| 2 | expires   | yes      | Minutes (1–1440)            |
| 3 | user      | yes      | User identifier             |
| 4 | admin     | no       | Admin identifier (impersonation) |

The payload contains 3 or 4 safe-hex integers delimited by `5`.

### 3.3 Salt

The salt defaults to the empty string `""`.  Applications should use explicit salts to separate contexts (e.g. `"session"` vs `"admin-impersonate"`).

### 3.4 Validation

A Session token is valid when all of the following hold:

1. The signature matches today's or yesterday's key.
2. The payload contains exactly 3 or 4 fields.
3. `issued_at + 1_750_750_750 ≤ now + 5` (not from the future).
4. `now < issued_at + 1_750_750_750 + expires × 60` (not expired).
5. `expires` is in range 1–1440.
6. If `admin` is present: `issued_at + 1_750_750_750 > user.admin_logout_at`.
7. If `admin` is absent: `issued_at + 1_750_750_750 > user.logout_at`.

Rules 6–7 require the application to look up the user record.  Users should not be cached for more than 60 seconds.

### 3.5 Cookie Guidance

- Set the cookie's `Expires`/`Max-Age` to match `issued_at + 1_750_750_750 + expires × 60`.
- Use `Secure`, `HttpOnly`, and at least `SameSite=Lax`.
- Do not accept Link or CSRF tokens in session cookies.

### 3.6 Admin Impersonation

When an admin impersonates a user, issue a Session token with:

- The `admin` field set to the admin's identifier.
- A purpose-specific salt (e.g. `"admin-impersonate"`).
- A very short expiration (1–2 minutes recommended).

Prefer delivering admin impersonation tokens via POST rather than URL.  On receipt, the application should respond with a `303 See Other` redirect to avoid POST replay.

### 3.7 Refreshing

Applications should re-issue Session tokens when payload data has changed or when at least **20% of the expiration time** has elapsed since `issued_at`.  This preserves at least 80% of the allowed session duration between user interactions without generating a new token on every request.

### 3.8 Logout

Logging out sets the user's `logout_at` to the current time, which invalidates all of that user's non-admin Session tokens.  This is inherently "logout from all devices" because validation compares `issued_at` against `logout_at`.

Logout does not affect Link tokens: a logout on device A should not invalidate a password reset link opened on device B.

For admin impersonation sessions, update `admin_logout_at` instead; this invalidates admin impersonation tokens without affecting the user's own sessions.

For security-sensitive events (password change, password reset completion, suspected compromise, e-mail change, account deactivation), update **all three** user timestamps: `logout_at`, `admin_logout_at`, and `last_nonce_at`.

## 4. Link Tokens

Link tokens are one-time-use tokens for URLs sent by e-mail (login links, verification, password resets).  They carry a 128-bit truncated signature.

### 4.1 Format

| Property          | Value    |
| ----------------- | -------- |
| Salt separator    | `=`      |
| Signature bits    | 128      |
| Signature chars   | 32       |
| Max token length  | 83 bytes |

### 4.2 Payload Fields

| # | Field     | Required | Description             |
| - | --------- | -------- | ----------------------- |
| 1 | issued_at | yes      | Seconds since BWT epoch |
| 2 | expires   | yes      | Minutes (1–1440)        |
| 3 | user      | yes      | User identifier         |

The payload always contains exactly 3 safe-hex integers delimited by `5`.

### 4.3 Salt

The `action` string serves as the salt (e.g. `"login"`, `"password-reset"`, `"verify-email"`).  This binds the token to a specific purpose; a token generated for one action cannot validate under a different action.

### 4.4 Validation

A Link token is valid when all of the following hold:

1. The signature matches today's or yesterday's key.
2. The payload contains exactly 3 fields.
3. `issued_at + 1_750_750_750 ≤ now + 5` (not from the future).
4. `now < issued_at + 1_750_750_750 + expires × 60` (not expired).
5. `expires` is in range 1–1440.
6. `issued_at + 1_750_750_750 > user.last_nonce_at`.

Rule 6 enforces one-time use.  The application must atomically update `last_nonce_at` when consuming the token (see §4.6).

### 4.5 Doorway Page

Link tokens in URLs are exposed in log files, browser history, and referrer headers.  Applications receiving a Link token via URL should implement a two-step process:

**Step 1 — Doorway page.** Display a landing page that:

- Sends these HTTP headers:
  - `Referrer-Policy: no-referrer`
  - `Cache-Control: no-store`
  - `Pragma: no-cache`
  - `X-Robots-Tag: noindex, nofollow`
- Performs **no action** and changes no state.
- Displays a confirmation that this is a secure process.
- Optionally summarizes the action about to be taken.
- Contains a POST form with the token in a hidden field.

**Step 2 — Action page.** When the user submits the form:

1. Reject the request unless it is a POST.
2. Atomically validate and consume the token (see §4.6).
3. Generate a new Session token as a session cookie with `issued_at = now + 1`.
4. Perform the intended action (login, password reset, etc.).

### 4.6 Atomic Consumption

To prevent reuse, Link tokens must be validated and invalidated in a single atomic storage operation that bypasses application-layer caches.  For example:

```sql
UPDATE users
SET last_nonce_at = GREATEST(last_nonce_at, NOW(), :new_session_issued_at)
WHERE id = :user_id
  AND is_active = TRUE
  AND last_nonce_at < :link_issued_at;
```

Here `:link_issued_at` is the Link token's `issued_at + 1_750_750_750` and `:new_session_issued_at` is the absolute `issued_at` of the new Session token about to be created.  Proceed only if exactly one row was updated.

In distributed systems, each link token action must route to a single authoritative service for atomic consumption, to guarantee that they can only ever be validated once.

## 5. CSRF Tokens

CSRF tokens guard against cross-site request forgery.  They carry a 96-bit truncated signature and the minimal possible payload.

### 5.1 Format

| Property          | Value    |
| ----------------- | -------- |
| Salt separator    | `~`      |
| Signature bits    | 96       |
| Signature chars   | 24       |
| Max token length  | 41 bytes |

### 5.2 Payload Fields

| # | Field | Required | Description   |
| - | ----- | -------- | ------------- |
| 1 | rand  | yes      | Random uint32 |

The payload contains exactly 1 safe-hex integer.  There are no `5` delimiters.

### 5.3 Salt

The `form_id` string (i.e. `"settings"`, `"change-password"`) appended with ":" and the safe-hex encoded user ID serves as the salt.  This binds the token to a specific form for a specific user; a token generated for one form cannot validate under a different form or user.

### 5.4 Validation

A CSRF token is valid when:

1. The signature matches today's or yesterday's key.
2. The payload contains exactly 1 field.

There is no explicit timestamp or expiration.  CSRF tokens are implicitly bounded by key rotation: a token is valid for at most ~48 hours (today's key + yesterday's key).

### 5.5 Usage

- Generate a 32-bit random integer.
- Embed the CSRF token in a hidden form field or custom HTTP header.
- Validate the token server-side on every state-changing request (POST, PUT, DELETE, etc.).
- Use a different `form_id` for each distinct form or action where practical.

## 6. User Record Fields

User records should include at least the following fields relevant to BWT validation:

| Field            | Type   | Purpose                                                        |
| ---------------- | ------ | -------------------------------------------------------------- |
| id               | uint64 | User identifier used in token payloads                      |
| logout_at        | uint64 | Last "logout from everywhere"; invalidates Session tokens      |
| admin_logout_at  | uint64 | Last admin impersonation logout; invalidates admin tokens      |
| last_nonce_at    | uint64 | Last Link token consumption; invalidates older Link tokens     |

Users should not be cached for more than 60 seconds in applications vs their local backing store.  In distributed systems, changes to user timestamps should propagate to every node within 5 minutes.

## 7. Security Considerations

- **Confidentiality:** BWT tokens are not encrypted.  Applications requiring confidential user IDs should allocate them pseudo-randomly.

- **Replay:** Like JWT, a stolen Session token can be reused from anywhere until logout or expiration.  Client binding is intentionally omitted because many clients have variable characteristics (e.g. multiple source IPs).

- **Link token exposure:** Link tokens in URLs may appear in logs, browser history, and referrer headers.  The doorway page pattern (§4.5) and atomic consumption (§4.6) are the primary mitigations.

- **CSRF token strength:** 96-bit truncated HMAC provides 2⁹⁶ forgery resistance, well above the security margin for online CSRF attacks.

- **Truncation:** Truncating HMAC-SHA-224 to 128 bits (Link) or 96 bits (CSRF) is acceptable per RFC 2104 §5 and NIST SP 800-107 Rev. 1 §5.3.4, providing at minimum 2⁹⁶ MAC forgery resistance.  (Note: NIST SP 800-107 Rev. 1 is scheduled for withdrawal; its guidance is being migrated to CMVP Implementation Guidance.)

- **Link tokens and logout:** Link token validation ignores `logout_at` by design.  A logout on device A should not invalidate a password reset link opened on device B.

- **Key generation:** Keys must be generated with a cryptographically secure random source (e.g. `/dev/urandom`, `getrandom(2)`, or equivalent).

## 8. Design Decisions

- **Scope:** BWT is limited to near-stateless authentication with logout ability.  The only payload fields are for expiration and identification.

- **Three forms:** Session, Link, and CSRF cover the three most common authentication token use cases with minimal overhead.  Each form uses the shortest signature that is cryptographically appropriate for its threat model.

- **Salt separators:** Each form uses a distinct separator character (`:`, `=`, `~`) in the HMAC input.  This makes tokens from different forms non-interchangeable even if the same key and salt were used.

- **Epoch offset:** The offset of 1,750,750,750 seconds reduces encoded timestamp size, which matters for URL-embedded tokens.

- **Determinism:** The same form, salt, and payload during the same second produce identical tokens.  BWT tokens are not unique identifiers.

- **Logout is global:** "Logout from all devices" is the only supported model because the mechanism depends on comparing a single `logout_at` against token timestamps.

- **Admin impersonation via Session:** Admin impersonation uses the existing Session form with an explicit salt and short expiration, rather than a separate token form.  This avoids additional complexity while providing clear separation through the salt.

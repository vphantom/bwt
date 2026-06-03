# Test Vectors — JSON Structure

This document describes the structure of `test-vectors.json` so that new implementations can write a test harness without reading the OCaml source.

The vectors are generated deterministically by `ocaml/bwt_vectors.ml` using the OCaml reference implementation.  Regenerate with:

```sh
dune exec ocaml/bwt_vectors.exe > test-vectors.json
```

## Top-Level Fields

| Field          | Type   | Description                                      |
| -------------- | ------ | ------------------------------------------------ |
| `spec_version` | string | Specification version (e.g. `"1.0rc5"`)          |
| `generated_by` | string | Generator identifier                             |
| `bwt_epoch`    | int    | BWT epoch offset in seconds (`1750750750`)       |
| `fixed_now`    | int    | Absolute UNIX timestamp used in most vectors     |
| `keys`         | object | Named HMAC keys (see below)                      |
| `session`      | object | Session token vectors (`positive`, `negative`)   |
| `link`         | object | Link token vectors (`positive`, `negative`)      |
| `csrf`         | object | CSRF token vectors (`positive`, `negative`)      |

## Keys

The `keys` object maps key names to hex-encoded (standard hex, not safe-hex) key bytes:

```json
{
  "today": "5454...5454",
  "yesterday": "5959...5959"
}
```

Throughout the vectors, keys are referenced **by name** (the strings `"today"` or `"yesterday"`).  The test harness must look up actual key bytes from this object and decode from hex.

## Null Convention

JSON `null` means "omit this optional parameter."  Applies to:

- `admin_id` — omit for non-admin sessions
- `admin_logout_at` — omit when no admin impersonation
- `yesterday` — omit to decode/validate with only the `today` key

## Time Values

All time values (`now`, `logout_at`, `admin_logout_at`, `last_nonce_at`, `fixed_now`) are **absolute UNIX timestamps** in seconds.  The BWT epoch is provided for reference but the test harness does not need to perform epoch arithmetic — the library under test handles that internally.

---

## Session Vectors

### Positive

Each positive vector tests the full encode → decode → validate pipeline.

```json
{
  "name": "descriptive name",
  "encode": {
    "key": "today",
    "salt": "",
    "now": 1760750750,
    "user_id": 1,
    "admin_id": null,
    "expires": 60
  },
  "expected_token": "...",
  "decode": {
    "today": "today",
    "yesterday": null,
    "salt": ""
  },
  "validate": {
    "now": 1760750750,
    "logout_at": 0,
    "admin_logout_at": null,
    "expected": "fresh"
  }
}
```

**Test procedure:**

1. **Encode:** Call `Session.encode` with the parameters in `encode`.  Assert the result equals `expected_token` exactly.
2. **Decode:** Call `Session.decode` on `expected_token` with the keys and salt from `decode`.  Assert success.  Assert decoded fields match `encode.now` (as `issued_at`), `encode.expires`, `encode.user_id`, and `encode.admin_id`.
3. **Validate:** Call `Session.validate` on the decoded token with the parameters from `validate`.  Check `expected`:
   - `"fresh"` — validate returns success with a "fresh" indicator (the token does not need re-issuing).
   - `"stale"` — validate returns success with a "stale" indicator (the token should be re-issued).

### Negative

Each negative vector asserts failure at a specific stage.

```json
{
  "name": "descriptive name",
  "token": "...",
  "should_fail_at": "decode",
  "decode": {
    "today": "today",
    "yesterday": null,
    "salt": ""
  }
}
```

Or, when `should_fail_at` is `"validate"`:

```json
{
  "name": "descriptive name",
  "token": "...",
  "should_fail_at": "validate",
  "decode": {
    "today": "today",
    "yesterday": null,
    "salt": ""
  },
  "validate": {
    "now": 1760750750,
    "logout_at": 0,
    "admin_logout_at": null
  }
}
```

**Test procedure:**

- **`"decode"`:** Call `Session.decode` with the given parameters.  Assert it returns an error.  Do not check the error message (it is implementation-specific).
- **`"validate"`:** Call `Session.decode` first — it must succeed.  Then call `Session.validate` with the parameters from `validate`.  Assert it returns an error.

The `validate` object is only present when `should_fail_at` is `"validate"`.

---

## Link Vectors

### Positive

```json
{
  "name": "descriptive name",
  "encode": {
    "key": "today",
    "action": "login",
    "now": 1760750750,
    "user_id": 1,
    "expires": 60
  },
  "expected_token": "...",
  "decode": {
    "today": "today",
    "yesterday": null,
    "action": "login"
  },
  "validate": {
    "now": 1760750750,
    "last_nonce_at": 0,
    "expected": "valid"
  }
}
```

**Test procedure:**

1. **Encode:** Call `Link.encode` with the parameters in `encode`.  Assert the result equals `expected_token`.
2. **Decode:** Call `Link.decode` on `expected_token` with keys and action from `decode`.  Assert success.  Assert decoded fields match `encode.now`, `encode.expires`, and `encode.user_id`.
3. **Validate:** Call `Link.validate` with `now` and `last_nonce_at` from `validate`.  The only expected result is `"valid"` (success).

### Negative

Same structure as Session negatives, but with `action` instead of `salt` in `decode`, and `last_nonce_at` instead of `logout_at`/`admin_logout_at` in `validate`:

```json
{
  "name": "descriptive name",
  "token": "...",
  "should_fail_at": "validate",
  "decode": {
    "today": "today",
    "yesterday": null,
    "action": "login"
  },
  "validate": {
    "now": 1760750870,
    "last_nonce_at": 0
  }
}
```

**Test procedure** is the same two-branch logic as Session negatives.

---

## CSRF Vectors

CSRF tokens have no separate decode step — validation is a single operation.

### Positive

```json
{
  "name": "descriptive name",
  "encode": {
    "key": "today",
    "rand": 42,
    "user_id": 1,
    "form_id": "login"
  },
  "expected_token": "...",
  "validate": {
    "today": "today",
    "yesterday": null,
    "form_id": "login",
    "user_id": 1,
    "expected": "valid"
  }
}
```

**Test procedure:**

1. **Encode:** Call `CSRF.encode` with the parameters in `encode`.  Assert the result equals `expected_token`.
2. **Validate:** Call `CSRF.validate` on `expected_token` with the parameters from `validate`.  The only expected result is `"valid"` (success).

### Negative

```json
{
  "name": "descriptive name",
  "token": "...",
  "should_fail_at": "validate",
  "validate": {
    "today": "today",
    "yesterday": null,
    "form_id": "login",
    "user_id": 1
  }
}
```

**Test procedure:** Call `CSRF.validate` with the given parameters.  Assert it returns an error.

Note: `should_fail_at` is always `"validate"` for CSRF since there is no separate decode step, but the field is present for structural consistency with Session and Link negatives.

---

## Summary of Expected Results

| Form    | Expected value | Meaning                                      |
| ------- | -------------- | -------------------------------------------- |
| Session | `"fresh"`      | Valid, does not need re-issuing               |
| Session | `"stale"`      | Valid, should be re-issued (≥20% time elapsed)|
| Link    | `"valid"`      | Valid                                         |
| CSRF    | `"valid"`      | Valid                                         |

Negative vectors have no `expected` field — the only assertion is that the operation fails.  Error messages are implementation-specific and must **not** be compared across implementations.

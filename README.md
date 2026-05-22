# Binary Web Token

[![license](https://img.shields.io/github/license/vphantom/bwt.svg?style=plastic)]() [![GitHub release](https://img.shields.io/github/release/vphantom/bwt.svg?style=plastic)]()

Inspired by the basic principles of JSON Web Tokens, but with an explicit requirement for server-side information in order to guarantee timely logouts, all in a format compact enough to use in e-mail verification links and cookies.

## SPECIFICATION

### Status

Release 1.0rc4 — 2026-05-22

### Implementations

* [OCaml](ocaml/README.md)
* [Perl 5](perl5/README.md) (planned)
* [Python](python/README.md) (planned)

### Format

Tokens are represented as 2 ASCII sections separated by character '9':

* **Payload** — Series of safe-hex unsigned 64-bit integers, without leading zeros, '5' delimited
* **Signature** — HMAC-SHA-224 signature of the final encoded payload, safe-hex encoded

A **full token** includes the full 224-bit signature, when length is not a constraint (i.e. HTTP cookies).  A **short token** truncates the signature to its initial 128 bits and is considered to be a one-time use token.  Decoders must accept both lengths.

Short token example: `HHHHHHHH5JJJJJ5KKKKKK5LLLLLL9WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW`

The maximum length of a token string is 124 bytes: `(4 * (64/4))` payload characters, 4 separators, `(224/4)` signature characters.

#### Safe-Hex

In some contexts such as e-mailed links, neither base 64 nor Crockford's base 32 or even regular hexadecimal can fully avoid false positives by overzealous profanity scanners. BWT uses an alternative hexadecimal character set with no vowel or vowel-looking characters and zero overlap with standard hex:

| Hex      | `0`  | `1`  | `2`  | `3`  | `4`  | `5`  | `6`  | `7`  | `8`  | `9`  | `A`  | `B`  | `C`  | `D`  | `E`  | `F`  |
| -------- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| Safe-Hex | `G`  | `H`  | `J`  | `K`  | `L`  | `M`  | `N`  | `P`  | `Q`  | `R`  | `S`  | `T`  | `V`  | `W`  | `X`  | `Z`  |

Only these 16 characters (`GHJKLMNPQRSTVWXZ`) are allowed, strictly in uppercase.

### Token Fields

Payload is composed of 3 or 4 integers:

* 1 — `issued_at` timestamp (UNIX Epoch minus 1,750,750,750)
* 2 — `expires` minutes (usually 30 for admins, 720 for others, maximum 1440)
* 3 — `user` some kind of ID
* 4 — `admin` some kind of ID if an admin is impersonating another user (optional)

Trailing separators should be trimmed.  (i.e. encoding `LL5ZZ5MM55` should be trimmed to `LL5ZZ5MM`)

When used as cookies, the cookie's expiration should match the token's `issued_at + 1_750_750_750 + (expires * 60)`.

### User Object Fields

Users should not be cached for more than 60 seconds in applications to keep the logout window short.  They should at least contain 3 fields:

* An unsigned integer ID
* `logout_at` timestamp of last logout by the user (invalidates user's own tokens)
* `admin_logout_at` timestamp of last logout by an admin impersonating the user (invalidates admin impersonation tokens only)
* `last_nonce_at` timestamp of last short token validation

### Validation

Several conditions must be met:

* The signature must match today's or yesterday's server key
* Implementations must use a constant-time comparison function
* The token's `issued_at + 1_750_750_750` should be at most 10 seconds in the future (to allow for clock skew between servers)
* The current timestamp must be less than the token's `issued_at + 1_750_750_750 + (expires * 60)`
* For admins impersonating users, the token's `issued_at + 1_750_750_750` must be greater than the user's `admin_logout_at`
* Creation time validation:
  * A token with `admin` set needs `(token.issued_at + 1_750_750_750) > user.admin_logout_at`
  * A full non-admin token needs `(token.issued_at + 1_750_750_750) > user.logout_at`
  * A short non-admin token needs `(token.issued_at + 1_750_750_750) > user.last_nonce_at`

Servers should keep a current key and the previous day's and accept tokens signed with either.  This ensures that tokens are always valid for their full lifetime regardless of time of day.  Keys should be generated with the best random generator available.  28 bytes (224 bits) is the minimum, ideally 64 bytes (512 bits, the SHA-224 block size).

### Short Tokens

Tokens with a truncated 128-bit signature should be considered "one-time use" or "handoff" tokens (similar to a NONCE), intended for URLs sent by e-mail such as login, verification or password reset links.  Web sites should not accept short tokens in HTTP session cookies.  Web sites receiving short tokens via URL should:

1. Display a doorway page greeting the user, which:
  * Performs no action
  * Displays a confirmation that this is a secure login process
  * Displays a summary of the action about to be taken, if any
  * Has a POST form including the token in a hidden field
2. When the user submits the form, the target action page then:
  * Performs no action unless it's serving a POST request
  * Sets the user's `last_nonce_at` (or `admin_logout_at` if there is an `admin_id`) to now, which invalidates all older short (or admin) tokens
  * Generates a new full token to use as session cookie (with `Secure` and `HttpOnly`)
  * Performs the intended action (login, password reset, etc.)

### Logout From Everywhere

When a user requests logging out, its `logout_at` (or `admin_logout_at` if the token has an `admin_id`) is set to now to invalidate all sessions and the cookie is deleted (`Set-Cookie` with empty content and expiration in the past).

### Refreshing

There is no need to generate new tokens at every web request, but waiting too long may make sessions time out prematurely from the user's last interaction.  Applications should issue new web tokens when payload data changed or when at least 20% of the expiration time has elapsed, thus preserving 80% of the allowed duration between interactions.

### Optional Context Salt

Especially for short tokens, applications may wish to prefix the payload server-side with a "context salt", a short string describing the context in which the token is being used, not included in the public payload.  This can help avoid tokens intended for a narrow application to be used for another.

For example, a password reset link short token "ABC" might be sent as "ABC" on the wire, but signed as "resetABC".  A password reset page would then also prefix the received payload with "reset" prior to comparing signatures.

## DESIGN DECISIONS

* The scope of BWT is limited to stateless authentication with logout ability. The only possible payload fields are thus for expiration and identification.

* Truncating HMAC-SHA-224 to 128 bits is acceptable per RFC 2104 §5 (output ≥ half the hash length, ≥ 80 bits) and NIST SP 800-107 Rev. 1 §5.3.4, providing 2<sup>128</sup> MAC forgery resistance.  (Note: NIST SP 800-107 Rev. 1 is scheduled for withdrawal; its guidance is being migrated to CMVP Implementation Guidance.)

* The time offset of 1,750,750,750 seconds was chosen to keep timestamps smaller and avoid typos in this constant itself.  This brings Epoch around June 2025, which was before this specification was finalized.

## ACKNOWLEDGMENTS

Graph X Design Inc. https://www.gxd.ca/ sponsored part of this project.

## LICENSE AND COPYRIGHT

Copyright (c) 2024-2026 Stéphane Lavergne <https://github.com/vphantom>

Distributed under the MIT (X11) License:
http://www.opensource.org/licenses/mit-license.php

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

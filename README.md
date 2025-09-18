# Binary Web Token

[![license](https://img.shields.io/github/license/vphantom/bwt.svg?style=plastic)]()

<!-- [![GitHub release](https://img.shields.io/github/release/vphantom/bwt.svg?style=plastic)]() -->

Heavily inspired by the basic principles of JSON Web Tokens, but with an explicit requirement for server-side information in order to guarantee timely logouts, all in a format small enough to use in e-mail verification links and cookies.

## SPECIFICATION

### Status

Release Candidate 3 — 2025-09-18

### Format

Like JWT, tokens are represented as 3 ASCII sections separated by periods `.`:

* **Header** — As of this writing, at least two 7-bit ASCII characters:
  * **First, payload format:**
    * `I` Series of safe-hex unsigned integers, colon (`:`) delimited
    * `p` Payload is a Protobuf message (BYO schema), encoded as base64url
    * `P` Payload is a Protobuf message (BYO schema), encoded as safe-hex
  * **Second, signature format:**
    * `h` An HMAC-SHA512-224 signature of the payload, encoded as base64url
    * `H` An HMAC-SHA512-224 signature of the payload, encoded as safe-hex
  * **Any additional characters, payload version:** Any alphanumeric characters to help applications distinguish payload structure differences over time, if needed.
* **Payload** — Data in the format specified by the header.
* **Signature** — Proof of integrity in the format specified by the header.

The 3 components are combined with periods: `HH.XXXXXXXX.XXXXXXXX`.

#### Safe-Hex

In some contexts such as e-mailed links, neither Base 64 nor Base 32 Crockford can fully avoid false positives with overzealous profanity scanners.  We define a backwards-compatible alternative hexadecimal character set which was carefully designed to solve the issue:

| Value | Char | Alternatives | Value | Char | Alternatives |
| ----- | ---- | ------------ | ----- | ---- | ------------ |
| `0`   | `Q`  | `O 0`        | `8`   | `H`  | `8`          |
| `1`   | `L`  | `I Y 1`      | `9`   | `9`  |              |
| `2`   | `Z`  | `2`          | `A`   | `K`  | `A`          |
| `3`   | `M`  | `N 3`        | `B`   | `P`  | `B`          |
| `4`   | `X`  | `4`          | `C`   | `C`  |              |
| `5`   | `W`  | `S 5`        | `D`   | `D`  |              |
| `6`   | `J`  | `G 6`        | `E`   | `R`  | `E`          |
| `7`   | `T`  | `7`          | `F`   | `V`  | `U F`        |

Encoders must use the "Char" column exclusively (set `QLZMXWJTH9KPCDRV`) and decoders must accept these and their alternatives, which includes regular hex.

### Token Fields

Payload must include at minimum:

* 1 — `issued_at` timestamp
* 2 — `expires` seconds (usually 1800 for admins, 43200 for others, 86400 for e-mail links)
* 3 — `is_nonce` flag (optional)
* 4 — `user` some kind of ID (optional)
* 5 — `admin` some kind of ID if an admin is impersonating another user (optional)

For list type payloads like `I`, optional fields may be truncated off the end of the list, but must be present when in the middle since they are positional. (i.e. `123456,1800` would be valid, equivalent to `123456,1800,0,0,0,...`)

When used as cookies, the cookie's expiration should match the token's `issued_at + expires`.

### User Object Fields

Users should not be cached for more than 60 seconds in applications to keep the logout window short.

* Some kind of unique ID
* `logout_at` timestamp of last logout
* `admin_logout_at` timestamp of last admin impersonation logout

### Validation

Several conditions must be met:

* The signature must match today's or yesterday's server key
* The current timestamp must be less than the token's `issued_at + expires`
* The token's `issued_at` must be greater than the user's `logout_at` (or for admins, the impersonated user's `admin_logout_at`)

### NONCE Flag

Tokens with the NONCE flag set must not be used for HTTP cookies.  Web sites receiving such tokens should:

* Display a doorway page greeting the user, saying they're logging in securely and offering a POST submit button to complete the process.
* The form must include the NONCE token in a hidden field.
* The form's target must refresh the token _without_ the NONCE flag (probably as a `Secure HttpOnly` cookie).
* The target page must also set the user's `logout_at` (or `admin_logout_at` if there is an `admin_id`) to 10 seconds ago, to make room for timing issues.

### Logout From Everywhere

When a user requests logging out, its `logout_at` (or `admin_logout_at` if the token has an `admin_id`) is touched and a new token must be emitted with cleared credentials.  (Or if there is nothing left in the token beyond its own timestamp and expiration, the cookie could be deleted outright.)

### Refreshing

Issue new web tokens when the ephemeral part of the payload (if any) changed or when at least 20% of the expiration time has elapsed.

## ACKNOWLEDGEMENTS

Graph X Design Inc. https://www.gxd.ca/ sponsored part of this project.

## LICENSE AND COPYRIGHT

Copyright (c) 2024-2025 Stéphane Lavergne <https://github.com/vphantom>

Distributed under the MIT (X11) License:
http://www.opensource.org/licenses/mit-license.php

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

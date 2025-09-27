# Binary Web Token

[![license](https://img.shields.io/github/license/vphantom/bwt.svg?style=plastic)]() [![GitHub release](https://img.shields.io/github/release/vphantom/bwt.svg?style=plastic)]()

Inspired by the basic principles of JSON Web Tokens, but with an explicit requirement for server-side information in order to guarantee timely logouts, all in a format compact enough to use in e-mail verification links and cookies.

## SPECIFICATION

### Status

Release 1.0 — 2025-09-27

### Format

Tokens are represented as 2 ASCII sections separated by a period `.`:

* **Payload** — Series of left-trimmed safe-hex unsigned 64-bit integers, colon (`:`) delimited
* **Signature** — HMAC-SHA512-224 safe-hex encoded signature of the final encoded payload

Left-trimming here refers to removing leading zeros prior to conversion.  Value `0x000fffff` should be encoded as `VVVVV`, not `QQQVVVVV`.

Full example: `LLLLLLLL:ZZZZZ:L:MMMMMM:XXXXXX.WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW`

#### Safe-Hex

In some contexts such as e-mailed links, neither Base 64 nor Base 32 Crockford or regular hex can fully avoid false positives by overzealous profanity scanners.  We define a backwards-compatible alternative hexadecimal character set which was carefully designed to solve the issue:

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

Encoders must use the "Char" column exclusively, in uppercase (set `QLZMXWJTH9KPCDRV`) and decoders must accept these and their alternatives, which includes regular hex, case insensitively.

### Token Fields

Payload is composed of up to 5 integers:

* 1 — `issued_at` timestamp (UNIX Epoch minus 1,750,750,750)
* 2 — `expires` minutes (usually 30 for admins, 720 for others, 1440 for e-mail links)
* 3 — `is_nonce` flag, set to 1 (safe-hex `L`) if true, omit if false (empty string)
* 4 — `user` some kind of ID (optional)
* 5 — `admin` some kind of ID if an admin is impersonating another user (optional)

Trailing separators should be trimmed.  (i.e. encoding `LL:ZZ:MM::` should be trimmed to `LL:ZZ:MM`)

When used as cookies, the cookie's expiration should match the token's `issued_at + 1_750_750_750 + expires`.

Note: the time offset of 1,750,750,750 seconds was chosen to keep timestamps smaller.  This brings Epoch around June 2025, which was before this specification was finalized, and was selected to minimize the risk of typos.

### User Object Fields

Users should not be cached for more than 60 seconds in applications to keep the logout window short.  They should at least contain 3 fields:

* An unsigned integer ID
* `logout_at` timestamp of last logout by the user (invalidates user's own tokens)
* `admin_logout_at` timestamp of last logout by an admin impersonating the user (invalidates admin impersonation tokens only)

### Validation

Several conditions must be met:

* The signature must match today's or yesterday's server key
* The current timestamp must be less than the token's `issued_at + 1_750_750_750 + expires`
* For admins impersonating users, the token's `issued_at + 1_750_750_750` must be greater than the user's `admin_logout_at`
* For regular users, the token's `issued_at + 1_750_750_750` must be greater than the user's `logout_at`

Note about server keys: servers should keep a current key and the previous day's, and accept tokens signed with either key.  This ensures that tokens are always valid for their full lifetime regardless of time of day.

### NONCE Flag

Tokens with the NONCE flag set must not be used for HTTP cookies.  Web sites receiving such tokens should:

* Display a doorway page greeting the user, saying they're logging in securely and offering a POST submit button to complete the process.
* The form must include the NONCE token in a hidden field.
* The form's target must refresh the token _without_ the NONCE flag (probably as a `Secure HttpOnly` cookie).
* The target page must also set the user's `logout_at` (or `admin_logout_at` if there is an `admin_id`) to 10 seconds ago, to make room for timing issues.

### Logout From Everywhere

When a user requests logging out, its `logout_at` (or `admin_logout_at` if the token has an `admin_id`) is touched and a new token must be emitted with cleared credentials.  (Or if there is nothing left in the token beyond its own timestamp and expiration, the cookie could be deleted outright.)

### Refreshing

Issue new web tokens when payload data changed or when at least 20% of the expiration time has elapsed.

## ACKNOWLEDGEMENTS

Graph X Design Inc. https://www.gxd.ca/ sponsored part of this project.

## LICENSE AND COPYRIGHT

Copyright (c) 2024-2025 Stéphane Lavergne <https://github.com/vphantom>

Distributed under the MIT (X11) License:
http://www.opensource.org/licenses/mit-license.php

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

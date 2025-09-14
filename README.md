# Binary Web Token

[![license](https://img.shields.io/github/license/vphantom/bwt.svg?style=plastic)]()

<!-- [![GitHub release](https://img.shields.io/github/release/vphantom/bwt.svg?style=plastic)]() -->

Heavily inspired by the basic principles of JSON Web Tokens, but with an explicit requirement for server-side information in order to guarantee timely logouts, all in a format small enough to use in e-mail verification links and cookies.

## SPECIFICATION

### Status

Release Candidate 2 - 2025-09-14

### Format

Like JWT, tokens are represented as 3 ASCII sections separated by periods `.`:

* **Header** — As of this writing, 3 characters:
  * **Payload format:**
    * **A** Series of LEB128 unsigned integers, encoded as base64url
    * **B** Series of PrefixVarint unsigned integers, encoded as base64url
    * **I** Payload is a Protobuf message (BYO schema), encoded as base64url
    * **J** Payload is a Protobuf message (BYO schema), gzipped, encoded as base64url
  * **Signature format:**
    * **A** Means the signature is an HMAC-SHA512-224 signature of the payload, encoded as base64url
  * **Payload version:** A character to help applications distinguish payload structure differences over time.
* **Payload** — Data in the format specified by the header.
* **Signature** — Proof of integrity in the format specified by the header.

The 3 components are combined with periods: `AAA.XXXXXXXX.XXXXXXXX`

#### LEB128

Little Endian Base 128 is a variable-length encoding for unsigned integers. Implemented by Google Protocol Buffers and native in Perl's `pack()`, the advantage of LEB128 is that any size integer may be represented (no 64-bit limit).  Each byte uses 7 bits for data and 1 bit as a continuation flag. If the most significant bit (MSB) is set, there are more bytes to follow. The data bits are combined in little-endian order to form the final integer.

**Decoding algorithm:**

1. Initialize result = 0, shift = 0
2. For each byte:
   - If MSB is set (byte ≥ 128), extract lower 7 bits and continue
   - Add (byte & 0x7F) << shift to result
   - Increase shift by 7
   - If MSB was clear, stop

**Examples:**

- `0x08` → 8 (single byte: MSB=0, value=8)
- `0x96 0x01` → 150
  - First byte: `0x96` = `10010110`, MSB=1, data=`0010110` (22)
  - Second byte: `0x01` = `00000001`, MSB=0, data=`0000001` (1)
  - Result: 22 + (1 × 128) = 150

#### PrefixVarint

An alternative variable-length encoding for unsigned integers that eliminates loops and most bit shifts compared to LEB128. The first byte's prefix determines how many additional bytes follow. PrefixVarint encodes 64-bit values in at most 9 bytes (vs 10 for LEB128) and is more CPU-efficient due to its branching structure instead of loops.  The first byte determines the integer size based on its prefix pattern. Any data bits in the first byte represent the least significant bits, with additional bytes following in little-endian order.

**Decoding table:**

| Byte (`c`) | Type   | Condition | Operation                          |
| ---------- | ------ | --------- | ---------------------------------- |
| `0_______` | 7-bit  | `< 128`   | `c`                                |
| `10______` | 14-bit | `< 192`   | `(read_u8le() << 6) + (c & 0x3F)`  |
| `110_____` | 21-bit | `< 224`   | `(read_u16le() << 5) + (c & 0x1F)` |
| `1110____` | 28-bit | `< 240`   | `(read_u24le() << 4) + (c & 0x0F)` |
| `11110___` | 35-bit | `< 248`   | `(read_u32le() << 3) + (c & 0x07)` |
| `111110__` | 42-bit | `< 252`   | `(read_u40le() << 2) + (c & 0x03)` |
| `1111110_` | 49-bit | `< 254`   | `(read_u48le() << 1) + (c & 0x01)` |
| `11111110` | 56-bit | `< 255`   | `read_u56le()`                     |
| `11111111` | 64-bit | `< 256`   | `read_u64le()`                     |

Where `read_uNNle()` reads the next NN-bit unsigned integer in little-endian byte order.

### Token Fields

Payload must include:

* 1 — `issued_at` timestamp (UNIX Epoch seconds - 1,750,750,750)
* 2 — `expires` seconds (usually 1800 for admins, 43200 for others, 86400 for e-mail links)
* 3 — `user_id` (optional)
* 4 — `admin_id` (optional)
* 5 — `nonce` flag (optional)
* ... — Any other ephemeral data. Bump your payload version if you make breaking changes.

For list type payloads like `A`, optional fields may be truncated off the end of the list, but must be present when in the middle since they are positional. (i.e. `123456,1800` would be valid, equivalent to `123456,1800,0,0,0,...`)

When used as cookies, the cookie's expiration should match the token's.

### User Object Fields

Users should not be cached for more than 60 seconds in applications to keep the logout window short.

* `id` integer unique identifier
* `logout_at` timestamp of last logout
* `admin_logout_at` timestamp of last admin impersonation logout

### Validation

Several conditions must be met:

* The signature must match today's or yesterday's server key
* The current timestamp must be less than the token's `issued_at + 1,750,750,750 + expires`
* The token's `issued_at + 1,750,750,750` must be greater than the user's `logout_at` (or for admins, the impersonated user's `admin_logout_at`)

Tokens with the `nonce` flag set must not be used for HTTP cookies: remove the flag first.

Links sent with a nonce token should lead to a doorway page greeting the user, saying they're logging in securely, and offering a POST submit button to complete the login procedure.  The page being posted to must then set the appropriate logout timestmap to 2 seconds ago to invalidate the nonce token.

### Logout From Everywhere

When a user requests logging out, its `logout_at` timestamp is touched (`admin_logout_at` if the session is an admin impersonating a the user) and a new token must be emitted with cleared credentials.  (Or if there is nothing left in the token beyond its own timestamp and expiration, the cookie could be deleted outright.)

### Refreshing

Issue new web tokens when the ephemeral part of the payload (if any) changed or when at least 20% of the expiration has elapsed.

## ACKNOWLEDGEMENTS

Graph X Design Inc. https://www.gxd.ca/ sponsored part of this project.

## LICENSE AND COPYRIGHT

Copyright (c) 2024-2025 Stéphane Lavergne <https://github.com/vphantom>

Distributed under the MIT (X11) License:
http://www.opensource.org/licenses/mit-license.php

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

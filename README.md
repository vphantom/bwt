# Binary Web Token

[![license](https://img.shields.io/github/license/vphantom/bwt.svg?style=plastic)]() [![GitHub release](https://img.shields.io/github/release/vphantom/bwt.svg?style=plastic)]()

Inspired by the basic principles of JSON Web Tokens, but with an explicit requirement for server-side information in order to guarantee timely logouts, all in a format compact enough to use in e-mail verification links and cookies.

BWT authenticates users. It does not provide CSRF protection, request authorization, form integrity, clickjacking protection, or replay protection for full session cookies. Applications using BWT in cookies must implement their own web security controls.

## Test Vectors

File [test-vectors.json](test-vectors.json) contains exhaustive tests to use when developing new implementations of BWT.  The initial set was created from the OCaml reference implementation using [ocaml/bwt_vectors.ml](ocaml/bwt_vectors.ml).

## STATUS

Release 1.0rc5 — 2026-05-26

### Implementations

* [OCaml](ocaml/README.md)
* [Perl 5](perl5/README.md) (planned)
* [Python](python/README.md) (planned)

## ACKNOWLEDGMENTS

Graph X Design Inc. https://www.gxd.ca/ sponsored part of this project.

## LICENSE AND COPYRIGHT

Copyright (c) 2024-2026 Stéphane Lavergne <https://github.com/vphantom>

Distributed under the MIT (X11) License:
http://www.opensource.org/licenses/mit-license.php

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

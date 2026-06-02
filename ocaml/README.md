# OCaml BWT

OCaml implementation of Binary Web Tokens.  This module provides:

* Safe-hex codec functions
* Full BWT codec functions

The only dependencies are:

* `digestif`
* `eqaf`

Development dependencies add:

* `alcotest`
* `bisect-ppx`
* `qcheck` and `qcheck-alcotest`

## Installation

This package is not published on OPAM.  Two common approaches are:

### OPAM Pin

To install as a normal switch-level package pinned to a specific version:

```sh
opam pin add ocaml-bwt 'git+https://github.com/vphantom/bwt.git#v1.0.0'
```

Then add `ocaml-bwt` to your `.opam` file's `depends` section.

### Vendored Submodule

Add this repository as a git submodule and let Dune discover it:

```sh
git submodule add https://github.com/vphantom/bwt.git vendor/bwt
```

In your project's root `dune` file, you probably want to suppress warnings from vendored code:

```
(vendored_dirs vendor)
```

Your libraries and executables can then depend on `bwt` directly.

## Cryptographically Secure Key Generation

You might want to use `mirage-crypto-rng`:

```ocaml
(* Once at start-up: *)
let () = Mirage_crypto_rng_unix.use_default ();;

(* Generate a key suitable for BWT: *)
let today = Mirage_crypto_rng.generate 64 in
```

## Known Limitations

* User and admin fields are represented with the `int` type, and thus numbers 2<sup>62</sup> and above are not supported and yield `Error Int_overflow`.

## Coding Style

- MLI files should include a brief summary of key design decisions to help future developers get situated quickly.
- Prefer:
  - Sticking to the Stdlib
  - Immutability where possible
  - TMC vs using `List.rev`
  - `Buffer` or `Printf` vs chains of `^`
  - `function` when matching on the last argument
  - Pipes vs parentheses for call chains (i.e. `foo a |> bar |> baz`)
  - Most global function arguments first (for currying) and subjects last (for piping)
  - Pattern matches vs if/else chains
  - Local functions to avoid lambdas spanning multiple lines or nesting more than two matches
  - `Seq.t` to `List.t` as an intermediary for conversions to reduce allocations
- Naming conventions:
  - Converters with `of_X`/`to_X` pairs

### Errors, Flow Control

#### Development Errors

Errors which should never happen in production deserve full stack traces.

* `assert` — _avoid_, use `failwith "…"` or `if expr then failwith "…"`
* `failwith "…"` — theoretically impossible states like negative array positions
* `invalid_arg "Module.func: …"` — caller misuse (developer error) with helpful hint
* `raise A_custom_exception` — non-developer errors which should still not happen in production

#### Exceptions For Flow Control

For hot-path flow control where bubbling a result value is impractical, use `raise_notrace`.  Use Stdlib's `End_of_file`, `Exit` and `Not_found` where appropriate, create custom exceptions for anything else.  Use custom exceptions instead of `Exit` for internal flow control which should not leak to your caller, for disambiguation.

#### Return Values

When it is expected that a function may not return its normal result in production, use `option`.  When there is useful information to pass along in the error case, use `result` instead.

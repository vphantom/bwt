(** Binary Web Tokens

    OCaml implementation of Binary Web Tokens.

    Integer width caveat: OCaml's [int] is 63 bits signed on 64-bit platforms,
    so the full unsigned 64-bit range cannot be represented. This module is
    limited to 62-bit positive integers. In practice this is not an issue for
    timestamps, expiration values, or user/admin IDs, but a safe-hex string
    whose decoded value would exceed [max_int] will produce
    [Error Int_overflow]. *)

type t = private {
  issued_at: int; (* Seconds since UNIX Epoch *)
  expires: int; (* Minutes after issued_at *)
  user: int;
  admin: int option;
  form: form;
  salt: string;
  is_stale: bool; (* True if 20%+ of expiry when [make] or [decode] was called *)
}

and form = Short | Full

(** [make ?form ?salt ?issued_at ?admin ~user expires] constructs a new token.
    [?form] defaults to [Full]. [salt] defaults to [""]. [issued_at] is in
    seconds since UNIX Epoch and defaults to now: this module handles the offset
    internally. *)
val make :
  ?form:form ->
  ?salt:string ->
  ?issued_at:int ->
  user:int ->
  ?admin:int ->
  int ->
  (t, string) result

(** [safehex_of_int n] encodes non-negative integer [n] as a left-trimmed
    safe-hex string. Zero encodes as ["G"]. Raises [Invalid_argument] if [n] is
    negative. *)
val safehex_of_int : int -> string

(** [safehex_to_int s] decodes a safe-hex string to an integer. Returns an error
    if [s] is empty or contains any character outside safe-hex. *)
val safehex_to_int : string -> (int, string) result

(** [encode ~today t] returns the signed token [t]. [today] is the current
    server signing key. [today] must be between 64 and 128 bytes in size, or
    else [Invalid_argument] is raised. *)
val encode : today:string -> t -> string

(** [decode ?salt ?form ?yesterday ~today s] verifies the signature of [s]
    against [today] (optionally falling back to [yesterday]) and parses its
    payload, using [salt] which defaults to [""]. Only [form] is accepted,
    defaulting to [Full].

    Obviously, it is up to the caller to validate the content of the token
    (user/admin IDs, timestamp comparisons, etc.) This function only verifies
    that the token is well-formed, has not been tampered with and has not
    reached its built-in expiration. *)
val decode :
  ?salt:string ->
  ?form:form ->
  ?yesterday:string ->
  today:string ->
  string ->
  (t, string) result

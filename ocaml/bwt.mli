(** Binary Web Tokens

    OCaml reference implementation of Binary Web Tokens.

    Integer width caveat: OCaml's [int] is 63 bits on 64-bit platforms, so the
    full unsigned 64-bit range cannot be represented. In practice this is not an
    issue for timestamps, expiration values, or user/admin IDs, but a safe-hex
    string whose decoded value would exceed [max_int] will produce incorrect
    results. *)

type t = private {
  issued_at: int; (* Seconds since UNIX Epoch *)
  expires: int; (* Minutes after issued_at *)
  user: int;
  admin: int option;
  form: form;
  salt: string option;
  is_stale: bool; (* True if 20% or more of expiration has elapsed *)
}

and form = Short | Full

type invalid =
  | Bad_admin
  | Bad_expiry
  | Bad_issue
  | Bad_signature
  | Bad_user
  | Expired
  | Future
  | Malformed

(** [make ?form ?salt ?issued_at ?admin ~user expires] constructs a new token.
    [?form] defaults to [Full] and [issued_at] defaults to now. *)
val make :
  ?form:form ->
  ?salt:string ->
  ?issued_at:int ->
  user:int ->
  ?admin:int ->
  int ->
  (t, invalid) result

(** [safehex_of_int n] encodes non-negative integer [n] as a left-trimmed
    safe-hex string. Zero encodes as ["G"]. Raises [Invalid_argument] if [n] is
    negative. *)
val safehex_of_int : int -> string

(** [int_of_safehex s] decodes a safe-hex string to an integer. Returns [None]
    if [s] is empty or contains any character outside safe-hex. *)
val int_of_safehex : string -> (int, invalid) result

(** [encode ~today t] returns the signed token [t]. [today] is the current
    server signing key. *)
val encode : today:string -> t -> string

(** [decode ?salt ?yesterday ~today s] verifies the signature of [s] against
    [today] (optionally falling back to [yesterday]) and parses its payload,
    using [salt] if provided. *)
val decode :
  ?salt:string ->
  ?yesterday:string ->
  today:string ->
  string ->
  (t, invalid) result

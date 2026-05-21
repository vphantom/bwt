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
  user: int option;
  admin: int option;
  is_nonce: bool;
  is_stale: bool; (* True if 20% or more of expiration has elapsed *)
}

(** [make ?nonce ?issued_at ?user ?admin expires] constructs a new token.
    [issued_at] defaults to the current time. *)
val make :
  ?nonce:bool -> ?issued_at:float -> ?user:int -> ?admin:int -> int -> t

(** [safehex_of_int n] encodes non-negative integer [n] as a left-trimmed
    safe-hex string. Zero encodes as ["G"]. Raises [Invalid_argument] if [n] is
    negative. *)
val safehex_of_int : int -> string

(** [int_of_safehex s] decodes a safe-hex string to an integer. Returns [None]
    if [s] is empty or contains any character outside safe-hex. *)
val int_of_safehex : string -> int option

(** [random_key ()] gets 64 bytes (512 bits) from [/dev/random] *)
val random_key : unit -> string

(** [encode ~today buf t] appends the encoded and signed token [t] to [buf].
    [today] is the current server signing key. *)
val encode : today:string -> Buffer.t -> t -> unit

(** [encode_str ~today t] wraps {!encode} to return a string. *)
val encode_str : today:string -> t -> string

(** [decode ?yesterday ~today s] verifies the signature of [s] against [today]
    (optionally falling back to [yesterday]) and parses its payload. Returns
    [None] if the signature is invalid, the safe-hex is malformed, or the
    payload structure is not recognized. *)
val decode : ?yesterday:string -> today:string -> string -> t option

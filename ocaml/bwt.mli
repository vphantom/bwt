(** Binary Web Tokens

    OCaml implementation of Binary Web Tokens.

    Integer width caveat: OCaml's [int] is 63 bits signed on 64-bit platforms,
    so the full unsigned 64-bit range cannot be represented. This module is
    limited to 62-bit positive integers. In practice this is not an issue for
    timestamps, expiration values, or user/admin IDs, but a safe-hex string
    whose decoded value would exceed [max_int] will produce
    [Error Int_overflow]. *)

(** {1 Safe Hex} *)

(** [safehex_of_int i] returns the safe-hex string representation of [i]. *)
val safehex_of_int : int -> string

(** [safehex_to_int s] returns the integer value of the safe-hex string [s]. *)
val safehex_to_int : string -> (int, string) result

(** {1 Session Tokens} *)

module Session : sig
  (** Session tokens are used for user authentication and authorization.

      Emitting tokens is a one-step operation with {!encode}.

      Receiving tokens is a three-step operation: {!decode}, fetch [user_id] and
      possibly [admin_id] from database if they're valid, then {!validate} with
      their logout timestamps.

      Receiving a stale token is a sign to emit a new cookie with a fresh token,
      whereas receiving a fresh token is a sign not to emit a cookie header. *)

  (** Session token *)
  type t

  (** [issued_at s] is the time the token was issued in seconds since UNIX
      Epoch. *)
  val issued_at : t -> int

  (** [expires s] is the number of minutes after [issued_at] that the token is
      valid. *)
  val expires : t -> int

  (** [user_id s] is the ID of the user associated with the token. *)
  val user_id : t -> int

  (** [admin_id s] is the ID of the admin impersonating [user_id], if any. *)
  val admin_id : t -> int option

  (** [encode key ?now ?salt user_id ?admin_id expires] creates a new session
      token signed with key [key].

      - [now] defaults to the current time
      - [salt] defaults to the empty string
      - [expires] is in minutes *)
  val encode :
    key:string ->
    ?now:int ->
    ?salt:string ->
    user_id:int ->
    ?admin_id:int ->
    int ->
    (string, string) result

  (** [decode ?salt ?yesterday today str] decodes [str] as a token signed with
      key [today] or [yesterday] with the same [salt] passed to {!encode}. The
      resulting token is proof that it wasn't tampered with, but is meaningless
      until it's been validated with {!validate}. *)
  val decode :
    ?salt:string ->
    ?yesterday:string ->
    today:string ->
    string ->
    (t, string) result

  (** [validate s ?now ?admin_logout_at logout_at] returns true if the token is
      valid and fresh, false if it is valid but not fresh (over 20% of its
      expiration has elapsed) and [Error] if it's invalid. *)
  val validate :
    ?now:int ->
    ?admin_logout_at:int ->
    logout_at:int ->
    t ->
    (bool, string) result
end

(** {1 Link Tokens} *)

module Link : sig
  (** Link tokens for one-time action authentication.

      Emitting tokens is a one-step operation with {!encode}.

      Receiving tokens is a three-step operation: {!decode}, fetch [user_id]
      from database if it's valid, then {!validate} with its NONCE timestamp. *)

  (** Link token *)
  type t

  (** [issued_at s] is the time the token was issued in seconds since UNIX
      Epoch. *)
  val issued_at : t -> int

  (** [expires s] is the number of minutes after [issued_at] that the token is
      valid. *)
  val expires : t -> int

  (** [user_id s] is the ID of the user associated with the token. *)
  val user_id : t -> int

  (** [encode key ?now action user_id expires] creates a new link token signed
      with key [key].

      - [now] defaults to the current time
      - [expires] is in minutes
      - [action] is a salt string to restrict the intent (i.e. ["pass_reset"])
  *)
  val encode :
    key:string ->
    ?now:int ->
    action:string ->
    user_id:int ->
    int ->
    (string, string) result

  (** [decode ?yesterday today action str] decodes [str] as a token signed with
      key [today] or [yesterday] and salted with [action] matching that passed
      to {!encode}. The resulting token is proof that it wasn't tampered with,
      but is meaningless until it's been validated with {!validate}. *)
  val decode :
    ?yesterday:string ->
    today:string ->
    action:string ->
    string ->
    (t, string) result

  (** [validate ?now last_nonce_at token] returns [Ok ()] if [token] is valid,
      [Error] otherwise. *)
  val validate : ?now:int -> last_nonce_at:int -> t -> (unit, string) result
end

(** {1 CSRF Tokens} *)

module CSRF : sig
  (** CSRF tokens for cross-site request forgery protection.

      CSRF tokens are simple strings which remain valid as long as the key used
      to sign it is the current or previous one. They sign a random integer as
      proof of origin.

      Emitting tokens is a one-step operation with {!encode}.

      Receiving tokens is a one-step operation with {!decode}. *)

  (** [encode key ?rand user_id form_id] creates a new CSRF token signed with
      [key], salted with [form_id] and [user_id]. Optional [rand] imposes the
      payload, useful for testing. *)
  val encode :
    key:string -> ?rand:int -> user_id:int -> string -> (string, string) result

  (** [validate ?yesterday today form_id user_id str] decodes [str] as a token
      signed with key [today] or [yesterday] and salted with [form_id] and
      [user_id]. An [Ok ()] result indicates that the token is valid for the
      specified form and user. *)
  val validate :
    ?yesterday:string ->
    today:string ->
    form_id:string ->
    user_id:int ->
    string ->
    (unit, string) result
end

let () = if Sys.int_size < 63 then failwith "Bwt: requires a 64-bit platform"
let ( let* ) = Result.bind
let ( ||| ) o default = Option.value ~default o
let[@inline] guard_res c e = if c then Ok () else Error e

type t = {
  issued_at: int; (* Encoded as -1,750,750,750 *)
  expires: int; (* Minutes after issued_at *)
  user: int;
  admin: int option;
  form: form;
  salt: string;
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
  | Int_overflow
  | Malformed

let epoch_offset = 1_750_750_750

let make ?(form = Full) ?(salt = "") ?issued_at ~user ?admin expires =
  let now = Unix.time () |> int_of_float in
  let issued_at = issued_at ||| now in
  let* () = guard_res (issued_at >= 0) Int_overflow in
  let* () = guard_res (issued_at >= epoch_offset) Bad_issue in
  let* () = guard_res (issued_at <= now + 5) Future in
  let* () = guard_res (expires >= 1) Bad_expiry in
  let* () = guard_res (expires <= 1440) Bad_expiry in
  let* () = guard_res (issued_at + (expires * 60) > now) Expired in
  let* () = guard_res (user >= 0) Bad_user in
  let* () = guard_res (Option.value ~default:0 admin >= 0) Bad_admin in
  (* NOTE: minutes * 60 * 20% -> minutes * 12 *)
  let is_stale = now >= issued_at + (expires * 12) in
  Ok { issued_at; expires; user; admin; form; salt; is_stale }
;;

exception Invalid_safehex

let nibble_of_char = function
  | 'G' -> 0
  | 'H' -> 1
  | 'J' -> 2
  | 'K' -> 3
  | 'L' -> 4
  | 'M' -> 5
  | 'N' -> 6
  | 'P' -> 7
  | 'Q' -> 8
  | 'R' -> 9
  | 'S' -> 10
  | 'T' -> 11
  | 'V' -> 12
  | 'W' -> 13
  | 'X' -> 14
  | 'Z' -> 15
  | _ -> raise_notrace Invalid_safehex
;;

let safehex_alphabet = "GHJKLMNPQRSTVWXZ"

let write_safehex_of_int buf n =
  if n < 0 then invalid_arg "Bwt.safehex_of_int: negative input";
  if n = 0
  then Buffer.add_char buf 'G'
  else (
    let rec find_start shift =
      if (n lsr shift) land 0xF <> 0 then shift else find_start (shift - 4)
    in
    let rec encode shift =
      if shift >= 0
      then (
        Buffer.add_char buf safehex_alphabet.[(n lsr shift) land 0xF];
        encode (shift - 4)
      )
    in
    encode (find_start 60)
  )
;;

let safehex_of_int n =
  let buf = Buffer.create 16 in
  write_safehex_of_int buf n; Buffer.contents buf
;;

let int_of_safehex s =
  match
    let len = String.length s in
    if len = 0 then raise_notrace Invalid_safehex;
    if len > 16 then raise_notrace Exit;
    if len > 1 && s.[0] = 'G' then raise_notrace Invalid_safehex;
    let first_nibble = nibble_of_char s.[0] in
    if len = 16 && first_nibble > 3 then raise_notrace Exit;
    let rec aux acc i =
      if i >= len
      then acc
      else aux ((acc lsl 4) lor nibble_of_char s.[i]) (i + 1)
    in
    aux first_nibble 1
  with
  | result -> Ok result
  | exception Exit -> Error Int_overflow
  | exception Invalid_safehex -> Error Malformed
;;

let write_safehex_of_string buf s =
  for i = 0 to String.length s - 1 do
    let b = Char.code s.[i] in
    Buffer.add_char buf safehex_alphabet.[b lsr 4];
    Buffer.add_char buf safehex_alphabet.[b land 0xF]
  done
;;

let string_of_safehex s =
  let len = String.length s in
  let* () = guard_res (len land 1 = 0) Malformed in
  match
    String.init (len / 2) (fun i ->
      let hi = nibble_of_char s.[i * 2] in
      let lo = nibble_of_char s.[(i * 2) + 1] in
      Char.chr ((hi lsl 4) lor lo)
  )
  with
  | result -> Ok result
  | exception Invalid_safehex -> Error Malformed
;;

let sign key payload =
  Digestif.SHA224.(hmac_string ~key payload |> to_raw_string)
;;

let encode ~today t =
  let kl = String.length today in
  if kl < 64 || kl > 128
  then invalid_arg "Bwt.encode: key length must be 64..128";
  let buf = Buffer.create 128 in
  let write_sep buf = Buffer.add_char buf '5' in
  write_safehex_of_int buf (t.issued_at - epoch_offset);
  write_sep buf;
  write_safehex_of_int buf t.expires;
  write_sep buf;
  write_safehex_of_int buf t.user;
  Option.iter (fun a -> write_sep buf; write_safehex_of_int buf a) t.admin;
  let signature =
    let hmac = sign today (t.salt ^ ":" ^ Buffer.contents buf) in
    match t.form with
    | Full -> hmac
    | Short -> String.sub hmac 0 16
  in
  Buffer.add_char buf '9';
  write_safehex_of_string buf signature;
  Buffer.contents buf
;;

let decode ?(salt = "") ?(form = Full) ?yesterday ~today s =
  let len = String.length s in
  let* () = guard_res (len <= 124) Malformed in
  let* payload, sig_hex =
    match String.split_on_char '9' s with
    | [ a; b ] -> Ok (a, b)
    | _ -> Error Malformed
  in
  let* sig_raw = string_of_safehex sig_hex in
  let* form' =
    match String.length sig_raw with
    | 16 -> Ok Short
    | 28 -> Ok Full
    | _ -> Error Malformed
  in
  let* () = guard_res (form = form') Malformed in
  let to_sign = salt ^ ":" ^ payload in
  let check_sig key =
    let computed = sign key to_sign in
    let truncated =
      match form with
      | Full -> computed
      | Short -> String.sub computed 0 16
    in
    Eqaf.equal truncated sig_raw
  in
  let* () =
    if check_sig today
    then Ok ()
    else (
      match yesterday with
      | Some y when check_sig y -> Ok ()
      | _ -> Error Bad_signature
    )
  in
  match String.split_on_char '5' payload with
  | [ iss; exp; usr ] ->
    let* issued_off = int_of_safehex iss in
    let* expires = int_of_safehex exp in
    let* user = int_of_safehex usr in
    make ~form ~salt ~issued_at:(issued_off + epoch_offset) ~user expires
  | [ iss; exp; usr; adm ] ->
    let* issued_off = int_of_safehex iss in
    let* expires = int_of_safehex exp in
    let* user = int_of_safehex usr in
    let* admin = int_of_safehex adm in
    make ~form ~salt ~issued_at:(issued_off + epoch_offset) ~user ~admin expires
  | _ -> Error Malformed
;;

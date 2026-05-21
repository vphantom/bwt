let ( let| ) = Option.bind
let[@inline] guard c = if c then Some () else None

type t = {
  issued_at: int; (* Encoded as -1,750,750,750 *)
  expires: int; (* Minutes after issued_at *)
  user: int option;
  admin: int option;
  is_nonce: bool; (* Encoded as 1 or omitted *)
  is_stale: bool;
}

let epoch_offset = 1_750_750_750

let is_stale issued_at expires =
  let now = Unix.time () |> int_of_float in
  let expires = issued_at + (expires * 12) in
  now > expires
;;

let make ?(nonce = false) ?(issued_at = Unix.time ()) ?user ?admin expires =
  if user = None && admin <> None
  then invalid_arg "Bwt.make: admin without user";
  let issued_at = int_of_float issued_at in
  if expires < 1 then invalid_arg "Bwt.make: negative or 0 expiration";
  if issued_at < 0 then invalid_arg "Bwt.make: negative issued_at";
  {
    issued_at;
    expires;
    user;
    admin;
    is_nonce = nonce;
    is_stale = is_stale issued_at expires;
  }
;;

let random_key () =
  let ic = open_in_bin "/dev/random" in
  Fun.protect ~finally:(fun () -> close_in ic) @@ fun () ->
  really_input_string ic 64
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
  match String.length s with
  | 0 -> None
  | len -> (
    let rec aux acc i =
      if i >= len
      then Some acc
      else aux ((acc lsl 4) lor nibble_of_char s.[i]) (i + 1)
    in
    match aux 0 0 with
    | result -> result
    | exception Invalid_safehex -> None
  )
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
  let| () = guard (len land 1 = 0) in
  match
    String.init (len / 2) (fun i ->
      let hi = nibble_of_char s.[i * 2] in
      let lo = nibble_of_char s.[(i * 2) + 1] in
      Char.chr ((hi lsl 4) lor lo)
  )
  with
  | result -> Some result
  | exception Invalid_safehex -> None
;;

let sign key payload =
  let hmac = Digestif.SHA224.(hmac_string ~key payload |> to_raw_string) in
  String.sub hmac 0 16
;;

let encode ~today buf t =
  let write_sep buf = Buffer.add_char buf '5' in
  write_safehex_of_int buf (t.issued_at - epoch_offset);
  write_sep buf;
  write_safehex_of_int buf t.expires;
  if t.user <> None || t.admin <> None
  then (
    write_sep buf;
    Option.iter (write_safehex_of_int buf) t.user
  );
  Option.iter (fun a -> write_sep buf; write_safehex_of_int buf a) t.admin;
  let signature = Buffer.contents buf |> sign today in
  Buffer.add_char buf (if t.is_nonce then '9' else '6');
  write_safehex_of_string buf signature
;;

let encode_str ~today t =
  let buf = Buffer.create 128 in
  encode ~today buf t; Buffer.contents buf
;;

let decode ?yesterday ~today s =
  let len = String.length s in
  let rec find_sep = function
    | i when i >= len -> None
    | i -> (
      match s.[i] with
      | '6' -> Some (i, false)
      | '9' -> Some (i, true)
      | _ -> find_sep (i + 1)
    )
  in
  let parse_payload payload is_nonce =
    match String.split_on_char '5' payload with
    | issued_str :: expires_str :: rest -> (
      let| issued_at = int_of_safehex issued_str in
      let| expires = int_of_safehex expires_str in
      let issued_at = issued_at + epoch_offset in
      let is_stale = is_stale issued_at expires in
      let base =
        { issued_at; expires; user = None; admin = None; is_nonce; is_stale }
      in
      match rest with
      | [] | [ "" ] | [ ""; _ ] -> Some base
      | [ u ] -> Some { base with user = int_of_safehex u }
      | [ u; a ] ->
        let user = int_of_safehex u in
        let admin = int_of_safehex a in
        let| () = guard (user <> None) in
        Some { base with user; admin }
      | _ -> None
    )
    | _ -> None
  in
  let| sep_pos, is_nonce = find_sep 0 in
  let sig_str = String.sub s (sep_pos + 1) (len - sep_pos - 1) in
  let| sig_raw = string_of_safehex sig_str in
  let| () = guard (String.length sig_raw = 16) in
  let payload = String.sub s 0 sep_pos in
  if sign today payload |> String.equal sig_raw
  then parse_payload payload is_nonce
  else
    let| yesterday = yesterday in
    if sign yesterday payload |> String.equal sig_raw
    then parse_payload payload is_nonce
    else None
;;

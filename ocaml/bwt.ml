let () =
  if Sys.int_size < 63 then failwith "Bwt: requires a 64-bit platform";
  Random.self_init ()
;;

let ( let@ ) = ( @@ )
let ( let* ) = Result.bind
let ( ||| ) o default = Option.value ~default o
let die_arg fmt = Printf.ksprintf invalid_arg ("Bwt." ^^ fmt)
let error fmt = Printf.ksprintf (fun s -> Error ("Bwt." ^ s)) fmt
(* let die fmt = Printf.ksprintf failwith ("Bwt: " ^^ fmt) *)

let guard_res c fmt =
  Printf.ksprintf (fun e f -> if c then f () else Error ("Bwt: " ^ e)) fmt
;;

let epoch_offset = 1_750_750_750

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

let safehex_to_int s =
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
  | exception Exit -> error "integer overflow"
  | exception Invalid_safehex -> error "bad safe-hex"
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
  let@ () = guard_res (len land 1 = 0) "malformed token" in
  match
    String.init (len / 2) (fun i ->
      let hi = nibble_of_char s.[i * 2] in
      let lo = nibble_of_char s.[(i * 2) + 1] in
      Char.chr ((hi lsl 4) lor lo)
  )
  with
  | result -> Ok result
  | exception Invalid_safehex -> error "bad safe-hex"
;;

let[@inline] validate_key k =
  let kl = String.length k in
  if kl < 64 || kl > 128 then die_arg "key length not in 64..128: %d" kl
;;

let[@inline] sign key payload =
  Digestif.SHA224.(hmac_string ~key payload |> to_raw_string)
;;

module Session = struct
  type t = { issued_at: int; expires: int; user_id: int; admin_id: int option }

  let issued_at s = s.issued_at
  let expires s = s.expires
  let user_id s = s.user_id
  let admin_id s = s.admin_id

  (* FIXME: needs review *)
  let encode ~key ?now ?(salt = "") ~user_id ?admin_id expires =
    validate_key key;
    let now = now ||| (Unix.time () |> int_of_float) in
    let@ () = guard_res (user_id >= 0) "Session.encode: negative user_id" in
    let@ () =
      guard_res
        (Option.value ~default:0 admin_id >= 0)
        "Session.encode: negative admin_id"
    in
    let@ () =
      guard_res (expires >= 1 && expires <= 1440) "Session.encode: bad expires"
    in
    let issued_off = now - epoch_offset in
    let@ () =
      guard_res (issued_off >= 0) "Session.encode: timestamp before epoch"
    in
    let buf = Buffer.create 124 in
    write_safehex_of_int buf issued_off;
    Buffer.add_char buf '5';
    write_safehex_of_int buf expires;
    Buffer.add_char buf '5';
    write_safehex_of_int buf user_id;
    Option.iter
      (fun a -> Buffer.add_char buf '5'; write_safehex_of_int buf a)
      admin_id;
    let payload = Buffer.contents buf in
    let hmac = sign key (salt ^ ":" ^ payload) in
    Buffer.add_char buf '9';
    write_safehex_of_string buf hmac;
    Ok (Buffer.contents buf)
  ;;

  (* FIXME: needs review *)
  let decode ?(salt = "") ?yesterday ~today str =
    validate_key today;
    Option.iter validate_key yesterday;
    let len = String.length str in
    let@ () = guard_res (len <= 124) "Session.decode: token too long" in
    let* payload, sig_hex =
      match String.split_on_char '9' str with
      | [ a; b ] -> Ok (a, b)
      | _ -> error "Session.decode: malformed token"
    in
    let* sig_raw = string_of_safehex sig_hex in
    let@ () =
      guard_res
        (String.length sig_raw = 28)
        "Session.decode: bad signature length"
    in
    let to_sign = salt ^ ":" ^ payload in
    let check_sig key =
      let computed = sign key to_sign in
      Eqaf.equal computed sig_raw
    in
    let* () =
      match check_sig today, yesterday with
      | true, _ -> Ok ()
      | false, Some y when check_sig y -> Ok ()
      | _ -> error "Session.decode: bad signature"
    in
    match String.split_on_char '5' payload with
    | [ iss; exp; usr ] ->
      let* issued_off = safehex_to_int iss in
      let* expires = safehex_to_int exp in
      let* user_id = safehex_to_int usr in
      let@ () =
        guard_res
          (issued_off <= max_int - epoch_offset)
          "Session.decode: integer overflow"
      in
      let@ () =
        guard_res
          (expires >= 1 && expires <= 1440)
          "Session.decode: bad expires"
      in
      Ok
        {
          issued_at = issued_off + epoch_offset;
          expires;
          user_id;
          admin_id = None;
        }
    | [ iss; exp; usr; adm ] ->
      let* issued_off = safehex_to_int iss in
      let* expires = safehex_to_int exp in
      let* user_id = safehex_to_int usr in
      let* admin_id = safehex_to_int adm in
      let@ () =
        guard_res
          (issued_off <= max_int - epoch_offset)
          "Session.decode: integer overflow"
      in
      let@ () =
        guard_res
          (expires >= 1 && expires <= 1440)
          "Session.decode: bad expires"
      in
      Ok
        {
          issued_at = issued_off + epoch_offset;
          expires;
          user_id;
          admin_id = Some admin_id;
        }
    | _ -> error "Session.decode: malformed payload"
  ;;

  let validate ?now ?admin_logout_at ~logout_at t =
    let now = now ||| (Unix.time () |> int_of_float) in
    let@ () =
      guard_res (t.issued_at <= now + 5) "Session.validate: future token"
    in
    let@ () =
      guard_res
        (now < t.issued_at + (t.expires * 60))
        "Session.validate: expired"
    in
    let* () =
      match t.admin_id, admin_logout_at with
      | Some _, Some alo when t.issued_at > alo -> Ok ()
      | Some _, Some _ -> error "Session.validate: admin logged out"
      | Some _, None -> error "Session.validate: missing admin_logout_at"
      | None, _ when t.issued_at > logout_at -> Ok ()
      | None, _ -> error "Session.validate: logged out"
    in
    Ok (now < t.issued_at + (t.expires * 12))
  ;;
end

module Link = struct
  type t = { issued_at: int; expires: int; user_id: int }

  let issued_at s = s.issued_at
  let expires s = s.expires
  let user_id s = s.user_id

  let encode ~key ?now ~action ~user_id expires =
    validate_key key;
    let now = now ||| (Unix.time () |> int_of_float) in
    let@ () = guard_res (action <> "") "Link.encode: empty action" in
    let@ () = guard_res (user_id >= 0) "Link.encode: negative user_id" in
    let@ () =
      guard_res (expires >= 1 && expires <= 1440) "Link.encode: bad expires"
    in
    let issued_off = now - epoch_offset in
    let@ () =
      guard_res (issued_off >= 0) "Link.encode: timestamp before epoch"
    in
    let buf = Buffer.create 83 in
    write_safehex_of_int buf issued_off;
    Buffer.add_char buf '5';
    write_safehex_of_int buf expires;
    Buffer.add_char buf '5';
    write_safehex_of_int buf user_id;
    let payload = Buffer.contents buf in
    let hmac = sign key (action ^ "=" ^ payload) in
    let sig_raw = String.sub hmac 0 16 in
    Buffer.add_char buf '9';
    write_safehex_of_string buf sig_raw;
    Ok (Buffer.contents buf)
  ;;

  let decode ?yesterday ~today ~action str =
    validate_key today;
    Option.iter validate_key yesterday;
    let len = String.length str in
    let@ () = guard_res (len <= 83) "Link.decode: token too long" in
    let* payload, sig_hex =
      match String.split_on_char '9' str with
      | [ a; b ] -> Ok (a, b)
      | _ -> error "Link.decode: malformed token"
    in
    let* sig_raw = string_of_safehex sig_hex in
    let@ () =
      guard_res (String.length sig_raw = 16) "Link.decode: bad signature length"
    in
    let to_sign = action ^ "=" ^ payload in
    let check_sig key =
      let computed = sign key to_sign in
      Eqaf.equal (String.sub computed 0 16) sig_raw
    in
    let* () =
      match check_sig today, yesterday with
      | true, _ -> Ok ()
      | false, Some y when check_sig y -> Ok ()
      | _ -> error "Link.decode: bad signature"
    in
    match String.split_on_char '5' payload with
    | [ iss; exp; usr ] ->
      let* issued_off = safehex_to_int iss in
      let* expires = safehex_to_int exp in
      let* user_id = safehex_to_int usr in
      let@ () =
        guard_res
          (issued_off <= max_int - epoch_offset)
          "Link.decode: integer overflow"
      in
      let@ () =
        guard_res (expires >= 1 && expires <= 1440) "Link.decode: bad expires"
      in
      Ok { issued_at = issued_off + epoch_offset; expires; user_id }
    | _ -> error "Link.decode: malformed payload"
  ;;

  let validate ?now ~last_nonce_at t =
    let now = now ||| (Unix.time () |> int_of_float) in
    let@ () =
      guard_res (t.issued_at <= now + 5) "Link.validate: future token"
    in
    let@ () =
      guard_res (now < t.issued_at + (t.expires * 60)) "Link.validate: expired"
    in
    let@ () =
      guard_res (t.issued_at > last_nonce_at) "Link.validate: no longer valid"
    in
    Ok ()
  ;;
end

module CSRF = struct
  let encode ~key ?rand ~user_id form_id =
    validate_key key;
    let@ () = guard_res (form_id <> "") "CSRF.encode: empty form_id" in
    let@ () = guard_res (user_id >= 0) "CSRF.encode: negative user_id" in
    let* rand =
      match rand with
      | Some r when r >= 0 && r <= 0xFFFFFFFF -> Ok r
      | Some _ -> error "CSRF.encode: rand out of range"
      | None -> Ok (Random.full_int 0xFFFFFFFF)
    in
    let buf = Buffer.create 41 in
    write_safehex_of_int buf rand;
    let payload = Buffer.contents buf in
    let salt = form_id ^ ":" ^ safehex_of_int user_id in
    let hmac = sign key (salt ^ "~" ^ payload) in
    let sig_raw = String.sub hmac 0 12 in
    Buffer.add_char buf '9';
    write_safehex_of_string buf sig_raw;
    Ok (Buffer.contents buf)
  ;;

  let validate ?yesterday ~today ~form_id ~user_id str =
    validate_key today;
    Option.iter validate_key yesterday;
    let len = String.length str in
    let@ () = guard_res (len <= 41) "CSRF.validate: token too long" in
    let* payload, sig_hex =
      match String.split_on_char '9' str with
      | [ a; b ] -> Ok (a, b)
      | _ -> error "CSRF.validate: malformed token"
    in
    let* sig_raw = string_of_safehex sig_hex in
    let@ () =
      guard_res
        (String.length sig_raw = 12)
        "CSRF.validate: bad signature length"
    in
    let@ () =
      guard_res
        (not (String.contains payload '5'))
        "CSRF.validate: malformed payload"
    in
    let* _rand = safehex_to_int payload in
    let salt = form_id ^ ":" ^ safehex_of_int user_id in
    let to_sign = salt ^ "~" ^ payload in
    let check_sig key =
      let computed = sign key to_sign in
      Eqaf.equal (String.sub computed 0 12) sig_raw
    in
    match check_sig today, yesterday with
    | true, _ -> Ok ()
    | false, Some y when check_sig y -> Ok ()
    | _ -> error "CSRF.validate: bad signature"
  ;;
end

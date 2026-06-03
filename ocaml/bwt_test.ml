(* NOTE: I'm using [Yojson.Basic.t] here but that assumes we'll stick to that
   for iterating through the test vectors. *)
let vectors = ref (`Assoc [])

(* Safe Hex *)

let test_safehex_of_int_zero () =
  Alcotest.(check string) "0 encodes to G" "G" (Bwt.safehex_of_int 0)
;;

let test_safehex_of_int_known_values () =
  Alcotest.(check string) "1" "H" (Bwt.safehex_of_int 1);
  Alcotest.(check string) "15" "Z" (Bwt.safehex_of_int 15);
  Alcotest.(check string) "16" "HG" (Bwt.safehex_of_int 16);
  Alcotest.(check string) "255" "ZZ" (Bwt.safehex_of_int 255);
  Alcotest.(check string) "256" "HGG" (Bwt.safehex_of_int 256)
;;

let test_safehex_of_int_negative () =
  match Bwt.safehex_of_int (-1) with
  | exception Invalid_argument msg ->
    Alcotest.(check string) "negative" "Bwt.safehex_of_int: negative input" msg
  | _ -> Alcotest.fail "expected Invalid_argument"
;;

let test_int_of_safehex_known_values () =
  Alcotest.(check (result int string)) "G" (Ok 0) (Bwt.safehex_to_int "G");
  Alcotest.(check (result int string)) "H" (Ok 1) (Bwt.safehex_to_int "H");
  Alcotest.(check (result int string)) "Z" (Ok 15) (Bwt.safehex_to_int "Z");
  Alcotest.(check (result int string)) "HG" (Ok 16) (Bwt.safehex_to_int "HG");
  Alcotest.(check (result int string)) "ZZ" (Ok 255) (Bwt.safehex_to_int "ZZ");
  Alcotest.(check (result int string)) "HGG" (Ok 256) (Bwt.safehex_to_int "HGG")
;;

let test_int_of_safehex_empty () =
  Alcotest.(check (result int string))
    "empty" (Error "Bwt.safehex: bad safe-hex") (Bwt.safehex_to_int "")
;;

let test_int_of_safehex_invalid () =
  Alcotest.(check (result int string))
    "lowercase" (Error "Bwt.safehex: bad safe-hex") (Bwt.safehex_to_int "g");
  Alcotest.(check (result int string))
    "digit" (Error "Bwt.safehex: bad safe-hex") (Bwt.safehex_to_int "0");
  Alcotest.(check (result int string))
    "hex letter" (Error "Bwt.safehex: bad safe-hex") (Bwt.safehex_to_int "A");
  Alcotest.(check (result int string))
    "mixed valid/invalid" (Error "Bwt.safehex: bad safe-hex")
    (Bwt.safehex_to_int "GA");
  Alcotest.(check (result int string))
    "leading zero" (Error "Bwt.safehex: bad safe-hex") (Bwt.safehex_to_int "GG");
  Alcotest.(check (result int string))
    "17 chars overflow" (Error "Bwt.safehex: integer overflow")
    (Bwt.safehex_to_int "HHGGGGGGGGGGGGGGG");
  Alcotest.(check (result int string))
    "2^62 overflow" (Error "Bwt.safehex: integer overflow")
    (Bwt.safehex_to_int "LGGGGGGGGGGGGGGG");
  Alcotest.(check (result int string))
    "max_int accepted" (Ok max_int)
    (Bwt.safehex_to_int "KZZZZZZZZZZZZZZZ")
;;

let qcheck_safehex_roundtrip =
  QCheck.Test.make ~name:"safehex round-trip" ~count:10_000
    QCheck.(int_range 0 max_int)
    (fun n -> Bwt.safehex_to_int (Bwt.safehex_of_int n) = Ok n)
;;

(* --- Safe-Hex String Tests --- *)

let test_safehex_of_int_max_int () =
  Alcotest.(check string)
    "max_int" "KZZZZZZZZZZZZZZZ"
    (Bwt.safehex_of_int max_int)
;;

let test_safehex_string_known_values () =
  (* Each byte maps to exactly 2 safe-hex chars *)
  Alcotest.(check string) "\\x00" "GG" (Bwt.safehex_of_string "\x00");
  Alcotest.(check string) "\\xff" "ZZ" (Bwt.safehex_of_string "\xff");
  Alcotest.(check string) "\\x00\\xff" "GGZZ" (Bwt.safehex_of_string "\x00\xff");
  Alcotest.(check string) "\\x1a" "HS" (Bwt.safehex_of_string "\x1a")
;;

let test_safehex_string_roundtrip () =
  let s = "\x00\xff\x42\xab" in
  Alcotest.(check (result string string))
    "roundtrip" (Ok s)
    (Bwt.safehex_to_string (Bwt.safehex_of_string s))
;;

let test_safehex_of_string_empty () =
  Alcotest.(check string) "empty encode" "" (Bwt.safehex_of_string "")
;;

let test_safehex_to_string_empty () =
  Alcotest.(check (result string string))
    "empty decode" (Ok "") (Bwt.safehex_to_string "")
;;

let test_safehex_to_string_odd_length () =
  (* Odd-length safe-hex can't represent whole bytes *)
  Alcotest.(check (result string string))
    "odd length 1" (Error "Bwt.safehex: malformed token")
    (Bwt.safehex_to_string "H");
  Alcotest.(check (result string string))
    "odd length 3" (Error "Bwt.safehex: malformed token")
    (Bwt.safehex_to_string "HHH")
;;

let test_safehex_to_string_invalid_char () =
  Alcotest.(check (result string string))
    "lowercase" (Error "Bwt.safehex: bad safe-hex")
    (Bwt.safehex_to_string "Ha");
  Alcotest.(check (result string string))
    "digit" (Error "Bwt.safehex: bad safe-hex")
    (Bwt.safehex_to_string "0G");
  Alcotest.(check (result string string))
    "hex letter" (Error "Bwt.safehex: bad safe-hex")
    (Bwt.safehex_to_string "AG")
;;

let qcheck_safehex_string_roundtrip =
  QCheck.Test.make ~name:"safehex string round-trip" ~count:5_000
    QCheck.(string_size (Gen.int_range 0 64))
    (fun s -> Bwt.safehex_to_string (Bwt.safehex_of_string s) = Ok s)
;;

(* --- Test Helpers --- *)

(* Keys must be 64–128 bytes. *)
let key_today = String.make 64 'T'
let key_yesterday = String.make 64 'Y'
let key_short = String.make 63 'X'
let key_long = String.make 129 'X'
let bwt_epoch = 1_750_750_750

(* A fixed "now" well after the BWT epoch. *)
let fixed_now = bwt_epoch + 10_000_000

(** Forge a Session token by signing [payload] with [key] and [salt], using
    Session's separator [:] and full 56-char signature. This lets us craft
    tokens with valid signatures over malformed payloads. *)
let forge_session ~key ~salt payload =
  let hmac_input = salt ^ ":" ^ payload in
  let raw_sig =
    Digestif.SHA224.(hmac_string ~key hmac_input |> to_raw_string)
  in
  let full_sig = Bwt.safehex_of_string raw_sig in
  let sig56 = String.sub full_sig 0 56 in
  payload ^ "9" ^ sig56
;;

(* ===== CSRF Tests ===== *)

let test_csrf_implicit_rand () =
  match Bwt.CSRF.encode ~key:key_today ~user_id:1 "login" with
  | Error e -> Alcotest.fail e
  | Ok tok ->
    Alcotest.(check (result unit string))
      "valid" (Ok ())
      (Bwt.CSRF.validate ~today:key_today ~form_id:"login" ~user_id:1 tok)
;;

let test_csrf_malformed_sig_short () =
  (* 23-char signature instead of 24 *)
  Alcotest.(check (result unit string))
    "sig short" (Error "Bwt.safehex: malformed token")
    (Bwt.CSRF.validate ~today:key_today ~form_id:"login" ~user_id:1
       "JS9HHHHHHHHHHHHHHHHHHHHHHH"
    )
;;

let test_csrf_malformed_sig_long () =
  (* 25-char signature instead of 24 *)
  Alcotest.(check (result unit string))
    "sig long" (Error "Bwt.safehex: malformed token")
    (Bwt.CSRF.validate ~today:key_today ~form_id:"login" ~user_id:1
       "JS9HHHHHHHHHHHHHHHHHHHHHHHHH"
    )
;;

let test_csrf_token_structure () =
  match Bwt.CSRF.encode ~key:key_today ~rand:42 ~user_id:1 "login" with
  | Error e -> Alcotest.fail e
  | Ok tok -> (
    let len = String.length tok in
    Alcotest.(check bool) "length <= 41" true (len <= 41);
    match String.index_opt tok '9' with
    | None -> Alcotest.fail "no separator"
    | Some i ->
      let sig_len = len - i - 1 in
      Alcotest.(check int) "signature length = 24" 24 sig_len
  )
;;

let test_csrf_max_token_length () =
  match
    Bwt.CSRF.encode ~key:key_today ~rand:4_294_967_295 ~user_id:1 "test"
  with
  | Error e -> Alcotest.fail e
  | Ok tok -> Alcotest.(check bool) "length <= 41" true (String.length tok <= 41)
;;

let test_csrf_rand_negative () =
  Alcotest.(check (result string string))
    "rand negative" (Error "Bwt.CSRF: rand out of range")
    (Bwt.CSRF.encode ~key:key_today ~rand:(-1) ~user_id:1 "login")
;;

let test_csrf_rand_over_uint32 () =
  Alcotest.(check (result string string))
    "rand > uint32" (Error "Bwt.CSRF: rand out of range")
    (Bwt.CSRF.encode ~key:key_today ~rand:4_294_967_296 ~user_id:1 "login")
;;

let test_csrf_bad_key_encode_short () =
  match Bwt.CSRF.encode ~key:key_short ~rand:42 ~user_id:1 "login" with
  | exception Invalid_argument _ -> ()
  | _ -> Alcotest.fail "expected Invalid_argument for short key"
;;

let test_csrf_bad_key_encode_long () =
  match Bwt.CSRF.encode ~key:key_long ~rand:42 ~user_id:1 "login" with
  | exception Invalid_argument _ -> ()
  | _ -> Alcotest.fail "expected Invalid_argument for long key"
;;

let test_csrf_bad_key_validate_short () =
  match Bwt.CSRF.encode ~key:key_today ~rand:42 ~user_id:1 "login" with
  | Error e -> Alcotest.fail e
  | Ok tok -> (
    match
      Bwt.CSRF.validate ~today:key_short ~form_id:"login" ~user_id:1 tok
    with
    | exception Invalid_argument _ -> ()
    | _ -> Alcotest.fail "expected Invalid_argument for short validate key"
  )
;;

let test_csrf_bad_key_validate_long () =
  match Bwt.CSRF.encode ~key:key_today ~rand:42 ~user_id:1 "login" with
  | Error e -> Alcotest.fail e
  | Ok tok -> (
    match Bwt.CSRF.validate ~today:key_long ~form_id:"login" ~user_id:1 tok with
    | exception Invalid_argument _ -> ()
    | _ -> Alcotest.fail "expected Invalid_argument for long validate key"
  )
;;

let qcheck_csrf_roundtrip =
  QCheck.Test.make ~name:"CSRF round-trip" ~count:1_000
    QCheck.(pair (int_range 0 4_294_967_295) (int_range 1 1_000_000))
    (fun (rand, user_id) ->
      match Bwt.CSRF.encode ~key:key_today ~rand ~user_id "qcheck" with
      | Error _ -> false
      | Ok tok ->
        Bwt.CSRF.validate ~today:key_today ~form_id:"qcheck" ~user_id tok
        = Ok ()
    )
;;

(* ===== Link Tests ===== *)

let test_link_implicit_now () =
  match Bwt.Link.encode ~key:key_today ~action:"login" ~user_id:1 60 with
  | Error e -> Alcotest.fail e
  | Ok tok -> (
    match Bwt.Link.decode ~today:key_today ~action:"login" tok with
    | Error e -> Alcotest.fail e
    | Ok t -> (
      match Bwt.Link.validate ~last_nonce_at:0 t with
      | Ok _ -> ()
      | Error e -> Alcotest.fail ("implicit now should work: " ^ e)
    )
  )
;;

let test_link_expires_zero () =
  Alcotest.(check (result string string))
    "expires=0" (Error "Bwt.Link: bad expires")
    (Bwt.Link.encode ~key:key_today ~now:fixed_now ~action:"login" ~user_id:1 0)
;;

let test_link_expires_over_max () =
  Alcotest.(check (result string string))
    "expires=1441" (Error "Bwt.Link: bad expires")
    (Bwt.Link.encode ~key:key_today ~now:fixed_now ~action:"login" ~user_id:1
       1441
    )
;;

let test_link_token_structure () =
  match
    Bwt.Link.encode ~key:key_today ~now:fixed_now ~action:"login" ~user_id:1 60
  with
  | Error e -> Alcotest.fail e
  | Ok tok -> (
    let len = String.length tok in
    Alcotest.(check bool) "length <= 83" true (len <= 83);
    match String.index_opt tok '9' with
    | None -> Alcotest.fail "no separator"
    | Some i ->
      let sig_len = len - i - 1 in
      Alcotest.(check int) "signature length = 32" 32 sig_len
  )
;;

let test_link_bad_key_decode_short () =
  match
    Bwt.Link.encode ~key:key_today ~now:fixed_now ~action:"login" ~user_id:1 60
  with
  | Error e -> Alcotest.fail e
  | Ok tok -> (
    match Bwt.Link.decode ~today:key_short ~action:"login" tok with
    | exception Invalid_argument _ -> ()
    | _ -> Alcotest.fail "expected Invalid_argument for short key"
  )
;;

let test_link_bad_key_decode_long () =
  match
    Bwt.Link.encode ~key:key_today ~now:fixed_now ~action:"login" ~user_id:1 60
  with
  | Error e -> Alcotest.fail e
  | Ok tok -> (
    match Bwt.Link.decode ~today:key_long ~action:"login" tok with
    | exception Invalid_argument _ -> ()
    | _ -> Alcotest.fail "expected Invalid_argument for long key"
  )
;;

let test_link_bad_key_yesterday_short () =
  match
    Bwt.Link.encode ~key:key_today ~now:fixed_now ~action:"login" ~user_id:1 60
  with
  | Error e -> Alcotest.fail e
  | Ok tok -> (
    match
      Bwt.Link.decode ~yesterday:key_short ~today:key_today ~action:"login" tok
    with
    | exception Invalid_argument _ -> ()
    | _ -> Alcotest.fail "expected Invalid_argument for short yesterday key"
  )
;;

let qcheck_link_roundtrip =
  QCheck.Test.make ~name:"Link round-trip" ~count:1_000
    QCheck.(
      triple
        (int_range (bwt_epoch + 1) (bwt_epoch + 100_000_000))
        (int_range 1 1440) (int_range 1 1_000_000)
    )
    (fun (now, expires, user_id) ->
      match
        Bwt.Link.encode ~key:key_today ~now ~action:"qcheck" ~user_id expires
      with
      | Error _ -> false
      | Ok tok -> (
        match Bwt.Link.decode ~today:key_today ~action:"qcheck" tok with
        | Error _ -> false
        | Ok t -> Bwt.Link.validate ~now ~last_nonce_at:0 t = Ok ()
      )
    )
;;

(* ===== Session Tests ===== *)

let test_session_implicit_now () =
  match Bwt.Session.encode ~key:key_today ~user_id:1 60 with
  | Error e -> Alcotest.fail e
  | Ok tok -> (
    match Bwt.Session.decode ~today:key_today tok with
    | Error e -> Alcotest.fail e
    | Ok t -> (
      match Bwt.Session.validate ~logout_at:0 t with
      | Ok _ -> ()
      | Error e -> Alcotest.fail ("implicit now should work: " ^ e)
    )
  )
;;

let test_session_expires_zero () =
  Alcotest.(check (result string string))
    "expires=0" (Error "Bwt.Session: bad expires")
    (Bwt.Session.encode ~key:key_today ~now:fixed_now ~user_id:1 0)
;;

let test_session_expires_negative () =
  Alcotest.(check (result string string))
    "expires=-1" (Error "Bwt.Session: bad expires")
    (Bwt.Session.encode ~key:key_today ~now:fixed_now ~user_id:1 (-1))
;;

let test_session_expires_over_max () =
  Alcotest.(check (result string string))
    "expires=1441" (Error "Bwt.Session: bad expires")
    (Bwt.Session.encode ~key:key_today ~now:fixed_now ~user_id:1 1441)
;;

let test_session_token_structure () =
  match Bwt.Session.encode ~key:key_today ~now:fixed_now ~user_id:1 60 with
  | Error e -> Alcotest.fail e
  | Ok tok -> (
    let len = String.length tok in
    Alcotest.(check bool) "length <= 124" true (len <= 124);
    match String.index_opt tok '9' with
    | None -> Alcotest.fail "no separator"
    | Some i ->
      let sig_len = len - i - 1 in
      Alcotest.(check int) "signature length = 56" 56 sig_len
  )
;;

let test_session_token_structure_with_admin () =
  match
    Bwt.Session.encode ~key:key_today ~now:fixed_now ~user_id:1 ~admin_id:99 60
  with
  | Error e -> Alcotest.fail e
  | Ok tok -> (
    let len = String.length tok in
    Alcotest.(check bool) "length <= 124 (with admin)" true (len <= 124);
    match String.index_opt tok '9' with
    | None -> Alcotest.fail "no separator"
    | Some i ->
      let sig_len = len - i - 1 in
      Alcotest.(check int) "signature length = 56" 56 sig_len
  )
;;

let test_session_bad_key_decode_short () =
  match Bwt.Session.encode ~key:key_today ~now:fixed_now ~user_id:1 60 with
  | Error e -> Alcotest.fail e
  | Ok tok -> (
    match Bwt.Session.decode ~today:key_short tok with
    | exception Invalid_argument _ -> ()
    | _ -> Alcotest.fail "expected Invalid_argument for short key"
  )
;;

let test_session_bad_key_decode_long () =
  match Bwt.Session.encode ~key:key_today ~now:fixed_now ~user_id:1 60 with
  | Error e -> Alcotest.fail e
  | Ok tok -> (
    match Bwt.Session.decode ~today:key_long tok with
    | exception Invalid_argument _ -> ()
    | _ -> Alcotest.fail "expected Invalid_argument for long key"
  )
;;

let test_session_bad_key_yesterday_short () =
  match Bwt.Session.encode ~key:key_today ~now:fixed_now ~user_id:1 60 with
  | Error e -> Alcotest.fail e
  | Ok tok -> (
    match Bwt.Session.decode ~yesterday:key_short ~today:key_today tok with
    | exception Invalid_argument _ -> ()
    | _ -> Alcotest.fail "expected Invalid_argument for short yesterday key"
  )
;;

let qcheck_session_roundtrip =
  QCheck.Test.make ~name:"Session round-trip" ~count:1_000
    QCheck.(
      quad
        (int_range (bwt_epoch + 1) (bwt_epoch + 100_000_000))
        (int_range 1 1440) (int_range 1 1_000_000)
        (option (int_range 1 1_000_000))
    )
    (fun (now, expires, user_id, admin_id) ->
      match
        Bwt.Session.encode ~key:key_today ~now ~user_id ?admin_id expires
      with
      | Error _ -> false
      | Ok tok -> (
        match Bwt.Session.decode ~today:key_today tok with
        | Error _ -> false
        | Ok t ->
          let admin_logout_at =
            match admin_id with
            | Some _ -> Some 0
            | None -> None
          in
          Bwt.Session.validate ~now ?admin_logout_at ~logout_at:0 t = Ok true
      )
    )
;;

(* --- Forged Session payload tests --- *)

(* Item 2: Oversized issued_at must return Int_overflow, not decode *)
let test_session_issued_at_overflow () =
  (* LGGGGGGGGGGGGGGG = 2^62, which overflows OCaml's 63-bit int *)
  let payload = "LGGGGGGGGGGGGGGG5H5H" in
  let tok = forge_session ~key:key_today ~salt:"" payload in
  match Bwt.Session.decode ~today:key_today tok with
  | Ok _ -> Alcotest.fail "oversized issued_at should not decode"
  | Error e ->
    Alcotest.(check string) "int overflow" "Bwt.safehex: integer overflow" e
;;

(* Item 9a: Token length exactly 124 is accepted structurally *)
let test_session_token_length_124 () =
  (* Session: sig=56 + separator=1 → payload must be 67 for total 124 *)
  (* 4 fields: "H" + "5" + "H" + "5" + "H" + "5" + 61×H = 6+61 = 67 *)
  let payload = "H5H5H5" ^ String.make 61 'H' in
  let tok = forge_session ~key:key_today ~salt:"" payload in
  Alcotest.(check int) "token is 124 chars" 124 (String.length tok);
  (* Must NOT be rejected for token length; int overflow is expected instead *)
  match Bwt.Session.decode ~today:key_today tok with
  | Ok _ -> Alcotest.fail "should fail (overflow) but not for length"
  | Error e ->
    if e = "Bwt.split_token: malformed token"
    then
      Alcotest.fail ("124-char token rejected for structure, not content: " ^ e)
;;

(* Item 9b: Token length 125 is rejected *)
let test_session_token_length_125 () =
  (* One char longer than max: payload = 68 → total = 125 *)
  let payload = "H5H5H5" ^ String.make 62 'H' in
  let tok = forge_session ~key:key_today ~salt:"" payload in
  Alcotest.(check int) "token is 125 chars" 125 (String.length tok);
  match Bwt.Session.decode ~today:key_today tok with
  | Ok _ -> Alcotest.fail "token length 125 should be rejected"
  | Error e ->
    Alcotest.(check string)
      "rejected for length" "Bwt.Session: token too long" e
;;

let load_vectors () =
  let path = "test-vectors.json" in
  vectors := Yojson.Basic.from_file path
;;

(* --- JSON accessor helpers --- *)

let json_string key = function
  | `Assoc l -> (
    match List.assoc_opt key l with
    | Some (`String s) -> s
    | _ -> failwith ("missing string: " ^ key)
  )
  | _ -> failwith "not an object"
;;

let json_int key = function
  | `Assoc l -> (
    match List.assoc_opt key l with
    | Some (`Int i) -> i
    | _ -> failwith ("missing int: " ^ key)
  )
  | _ -> failwith "not an object"
;;

let json_list key = function
  | `Assoc l -> (
    match List.assoc_opt key l with
    | Some (`List l) -> l
    | _ -> failwith ("missing list: " ^ key)
  )
  | _ -> failwith "not an object"
;;

let json_assoc key = function
  | `Assoc l -> (
    match List.assoc_opt key l with
    | Some (`Assoc _ as a) -> a
    | _ -> failwith ("missing assoc: " ^ key)
  )
  | _ -> failwith "not an object"
;;

let json_int_opt key = function
  | `Assoc l -> (
    match List.assoc_opt key l with
    | Some (`Int i) -> Some i
    | Some `Null | None -> None
    | _ -> failwith ("bad optional int: " ^ key)
  )
  | _ -> failwith "not an object"
;;

let json_string_opt key = function
  | `Assoc l -> (
    match List.assoc_opt key l with
    | Some (`String s) -> Some s
    | Some `Null | None -> None
    | _ -> failwith ("bad optional string: " ^ key)
  )
  | _ -> failwith "not an object"
;;

let hex_to_string h =
  let len = String.length h in
  let buf = Buffer.create (len / 2) in
  let digit = function
    | '0' .. '9' as c -> Char.code c - Char.code '0'
    | 'a' .. 'f' as c -> Char.code c - Char.code 'a' + 10
    | _ -> failwith "bad hex char"
  in
  for i = 0 to (len / 2) - 1 do
    let hi = digit h.[2 * i] in
    let lo = digit h.[(2 * i) + 1] in
    Buffer.add_char buf (Char.chr ((hi lsl 4) lor lo))
  done;
  Buffer.contents buf
;;

let vector_key name =
  json_assoc "keys" !vectors |> json_string name |> hex_to_string
;;

(* --- Vector tests: metadata --- *)

let test_vectors_metadata () =
  let v = !vectors in
  Alcotest.(check string) "spec_version" "1.0rc5" (json_string "spec_version" v);
  Alcotest.(check string)
    "generated_by" "ocaml/bwt_vectors.ml"
    (json_string "generated_by" v);
  Alcotest.(check int) "bwt_epoch" 1_750_750_750 (json_int "bwt_epoch" v);
  Alcotest.(check int) "fixed_now" 1_760_750_750 (json_int "fixed_now" v)
;;

let test_vectors_keys () =
  let keys = json_assoc "keys" !vectors in
  let today = json_string "today" keys in
  let yesterday = json_string "yesterday" keys in
  (* 64-byte keys → 128 hex chars *)
  Alcotest.(check int) "today key hex length" 128 (String.length today);
  Alcotest.(check int) "yesterday key hex length" 128 (String.length yesterday);
  (* Keys must differ *)
  Alcotest.(check bool) "keys differ" true (today <> yesterday)
;;

let test_vectors_known_sections () =
  let known =
    [
      "spec_version";
      "generated_by";
      "bwt_epoch";
      "fixed_now";
      "keys";
      "session";
      "link";
      "csrf";
    ]
  in
  match !vectors with
  | `Assoc l ->
    List.iter
      (fun (k, _) ->
        if not (List.mem k known)
        then Alcotest.failf "unknown top-level section in vectors JSON: %s" k
      )
      l
  | _ -> Alcotest.fail "vectors JSON is not an object"
;;

let test_vectors_sections_nonempty () =
  let v = !vectors in
  let session = json_assoc "session" v in
  let link = json_assoc "link" v in
  let csrf = json_assoc "csrf" v in
  Alcotest.(check bool)
    "session positive non-empty" true
    (json_list "positive" session |> List.length > 0);
  Alcotest.(check bool)
    "session negative non-empty" true
    (json_list "negative" session |> List.length > 0);
  Alcotest.(check bool)
    "link positive non-empty" true
    (json_list "positive" link |> List.length > 0);
  Alcotest.(check bool)
    "link negative non-empty" true
    (json_list "negative" link |> List.length > 0);
  Alcotest.(check bool)
    "csrf positive non-empty" true
    (json_list "positive" csrf |> List.length > 0);
  Alcotest.(check bool)
    "csrf negative non-empty" true
    (json_list "negative" csrf |> List.length > 0)
;;

(* --- Vector tests: CSRF --- *)

let vector_csrf_positive v =
  let name = json_string "name" v in
  Alcotest.test_case name `Quick (fun () ->
    let enc = json_assoc "encode" v in
    let expected = json_string "expected_token" v in
    let val_ = json_assoc "validate" v in
    (* Encode *)
    let key = vector_key (json_string "key" enc) in
    let rand = json_int "rand" enc in
    let user_id = json_int "user_id" enc in
    let form_id = json_string "form_id" enc in
    Alcotest.(check (result string string))
      "encode" (Ok expected)
      (Bwt.CSRF.encode ~key ~rand ~user_id form_id);
    (* Validate *)
    let today = vector_key (json_string "today" val_) in
    let yesterday = json_string_opt "yesterday" val_ |> Option.map vector_key in
    let vform = json_string "form_id" val_ in
    let vuser = json_int "user_id" val_ in
    Alcotest.(check (result unit string))
      "validate" (Ok ())
      (Bwt.CSRF.validate ?yesterday ~today ~form_id:vform ~user_id:vuser
         expected
      )
)
;;

let vector_csrf_negative v =
  let name = json_string "name" v in
  Alcotest.test_case name `Quick (fun () ->
    let token = json_string "token" v in
    let val_ = json_assoc "validate" v in
    let today = vector_key (json_string "today" val_) in
    let yesterday = json_string_opt "yesterday" val_ |> Option.map vector_key in
    let form_id = json_string "form_id" val_ in
    let user_id = json_int "user_id" val_ in
    match Bwt.CSRF.validate ?yesterday ~today ~form_id ~user_id token with
    | Ok () -> Alcotest.fail "expected validation to fail"
    | Error _ -> ()
)
;;

(* --- Vector tests: Session --- *)

let vector_session_positive v =
  let name = json_string "name" v in
  Alcotest.test_case name `Quick (fun () ->
    let enc = json_assoc "encode" v in
    let expected = json_string "expected_token" v in
    let dec = json_assoc "decode" v in
    let val_ = json_assoc "validate" v in
    (* Encode *)
    let key = vector_key (json_string "key" enc) in
    let salt = json_string "salt" enc in
    let now = json_int "now" enc in
    let user_id = json_int "user_id" enc in
    let admin_id = json_int_opt "admin_id" enc in
    let expires = json_int "expires" enc in
    Alcotest.(check (result string string))
      "encode" (Ok expected)
      (Bwt.Session.encode ~key ~now ~salt ~user_id ?admin_id expires);
    (* Decode *)
    let today = vector_key (json_string "today" dec) in
    let yesterday = json_string_opt "yesterday" dec |> Option.map vector_key in
    let dec_salt = json_string "salt" dec in
    match Bwt.Session.decode ?yesterday ~today ~salt:dec_salt expected with
    | Error e -> Alcotest.fail ("decode: " ^ e)
    | Ok t -> (
      Alcotest.(check int) "issued_at" now (Bwt.Session.issued_at t);
      Alcotest.(check int) "expires" expires (Bwt.Session.expires t);
      Alcotest.(check int) "user_id" user_id (Bwt.Session.user_id t);
      Alcotest.(check (option int)) "admin_id" admin_id (Bwt.Session.admin_id t);
      (* Validate *)
      let vnow = json_int "now" val_ in
      let logout_at = json_int "logout_at" val_ in
      let admin_logout_at = json_int_opt "admin_logout_at" val_ in
      let expected_result = json_string "expected" val_ in
      match expected_result with
      | "fresh" ->
        Alcotest.(check (result bool string))
          "validate" (Ok true)
          (Bwt.Session.validate ~now:vnow ?admin_logout_at ~logout_at t)
      | "stale" ->
        Alcotest.(check (result bool string))
          "validate" (Ok false)
          (Bwt.Session.validate ~now:vnow ?admin_logout_at ~logout_at t)
      | s -> Alcotest.failf "unknown expected result: %s" s
    )
)
;;

let vector_session_negative v =
  let name = json_string "name" v in
  Alcotest.test_case name `Quick (fun () ->
    let token = json_string "token" v in
    let fail_at = json_string "should_fail_at" v in
    let dec = json_assoc "decode" v in
    let today = vector_key (json_string "today" dec) in
    let yesterday = json_string_opt "yesterday" dec |> Option.map vector_key in
    let salt = json_string "salt" dec in
    match fail_at with
    | "decode" -> (
      match Bwt.Session.decode ?yesterday ~today ~salt token with
      | Ok _ -> Alcotest.fail "expected decode to fail"
      | Error _ -> ()
    )
    | "validate" -> (
      match Bwt.Session.decode ?yesterday ~today ~salt token with
      | Error e -> Alcotest.fail ("decode should succeed: " ^ e)
      | Ok t -> (
        let val_ = json_assoc "validate" v in
        let now = json_int "now" val_ in
        let logout_at = json_int "logout_at" val_ in
        let admin_logout_at = json_int_opt "admin_logout_at" val_ in
        match Bwt.Session.validate ~now ?admin_logout_at ~logout_at t with
        | Ok _ -> Alcotest.fail "expected validate to fail"
        | Error _ -> ()
      )
    )
    | s -> Alcotest.failf "unknown should_fail_at: %s" s
)
;;

let vector_session_tests () =
  let section = json_assoc "session" !vectors in
  let positives =
    json_list "positive" section |> List.map vector_session_positive
  in
  let negatives =
    json_list "negative" section |> List.map vector_session_negative
  in
  positives @ negatives
;;

(* --- Vector tests: Link --- *)

let vector_link_positive v =
  let name = json_string "name" v in
  Alcotest.test_case name `Quick (fun () ->
    let enc = json_assoc "encode" v in
    let expected = json_string "expected_token" v in
    let dec = json_assoc "decode" v in
    let val_ = json_assoc "validate" v in
    (* Encode *)
    let key = vector_key (json_string "key" enc) in
    let now = json_int "now" enc in
    let action = json_string "action" enc in
    let user_id = json_int "user_id" enc in
    let expires = json_int "expires" enc in
    Alcotest.(check (result string string))
      "encode" (Ok expected)
      (Bwt.Link.encode ~key ~now ~action ~user_id expires);
    (* Decode *)
    let today = vector_key (json_string "today" dec) in
    let yesterday = json_string_opt "yesterday" dec |> Option.map vector_key in
    let dec_action = json_string "action" dec in
    match Bwt.Link.decode ?yesterday ~today ~action:dec_action expected with
    | Error e -> Alcotest.fail ("decode: " ^ e)
    | Ok t -> (
      Alcotest.(check int) "issued_at" now (Bwt.Link.issued_at t);
      Alcotest.(check int) "expires" expires (Bwt.Link.expires t);
      Alcotest.(check int) "user_id" user_id (Bwt.Link.user_id t);
      (* Validate *)
      let vnow = json_int "now" val_ in
      let last_nonce_at = json_int "last_nonce_at" val_ in
      let expected_result = json_string "expected" val_ in
      match expected_result with
      | "valid" ->
        Alcotest.(check (result unit string))
          "validate" (Ok ())
          (Bwt.Link.validate ~now:vnow ~last_nonce_at t)
      | s -> Alcotest.failf "unknown expected result: %s" s
    )
)
;;

let vector_link_negative v =
  let name = json_string "name" v in
  Alcotest.test_case name `Quick (fun () ->
    let token = json_string "token" v in
    let fail_at = json_string "should_fail_at" v in
    let dec = json_assoc "decode" v in
    let today = vector_key (json_string "today" dec) in
    let yesterday = json_string_opt "yesterday" dec |> Option.map vector_key in
    let action = json_string "action" dec in
    match fail_at with
    | "decode" -> (
      match Bwt.Link.decode ?yesterday ~today ~action token with
      | Ok _ -> Alcotest.fail "expected decode to fail"
      | Error _ -> ()
    )
    | "validate" -> (
      match Bwt.Link.decode ?yesterday ~today ~action token with
      | Error e -> Alcotest.fail ("decode should succeed: " ^ e)
      | Ok t -> (
        let val_ = json_assoc "validate" v in
        let now = json_int "now" val_ in
        let last_nonce_at = json_int "last_nonce_at" val_ in
        match Bwt.Link.validate ~now ~last_nonce_at t with
        | Ok () -> Alcotest.fail "expected validate to fail"
        | Error _ -> ()
      )
    )
    | s -> Alcotest.failf "unknown should_fail_at: %s" s
)
;;

let vector_link_tests () =
  let section = json_assoc "link" !vectors in
  let positives =
    json_list "positive" section |> List.map vector_link_positive
  in
  let negatives =
    json_list "negative" section |> List.map vector_link_negative
  in
  positives @ negatives
;;

let vector_csrf_tests () =
  let section = json_assoc "csrf" !vectors in
  let positives =
    json_list "positive" section |> List.map vector_csrf_positive
  in
  let negatives =
    json_list "negative" section |> List.map vector_csrf_negative
  in
  positives @ negatives
;;

let () =
  let direct_tests =
    [
      ( "Safe-Hex",
        [
          Alcotest.test_case "safehex_of_int zero" `Quick
            test_safehex_of_int_zero;
          Alcotest.test_case "safehex_of_int known values" `Quick
            test_safehex_of_int_known_values;
          Alcotest.test_case "safehex_of_int negative" `Quick
            test_safehex_of_int_negative;
          Alcotest.test_case "safehex_to_int known values" `Quick
            test_int_of_safehex_known_values;
          Alcotest.test_case "safehex_to_int empty" `Quick
            test_int_of_safehex_empty;
          Alcotest.test_case "safehex_to_int invalid" `Quick
            test_int_of_safehex_invalid;
          QCheck_alcotest.to_alcotest qcheck_safehex_roundtrip;
          Alcotest.test_case "safehex_of_int max_int" `Quick
            test_safehex_of_int_max_int;
          Alcotest.test_case "safehex string known values" `Quick
            test_safehex_string_known_values;
          Alcotest.test_case "safehex string round-trip" `Quick
            test_safehex_string_roundtrip;
          Alcotest.test_case "safehex_of_string empty" `Quick
            test_safehex_of_string_empty;
          Alcotest.test_case "safehex_to_string empty" `Quick
            test_safehex_to_string_empty;
          Alcotest.test_case "safehex_to_string odd length" `Quick
            test_safehex_to_string_odd_length;
          Alcotest.test_case "safehex_to_string invalid char" `Quick
            test_safehex_to_string_invalid_char;
          QCheck_alcotest.to_alcotest qcheck_safehex_string_roundtrip;
        ] );
      ( "CSRF",
        [
          Alcotest.test_case "implicit rand" `Quick test_csrf_implicit_rand;
          Alcotest.test_case "malformed: sig too short" `Quick
            test_csrf_malformed_sig_short;
          Alcotest.test_case "malformed: sig too long" `Quick
            test_csrf_malformed_sig_long;
          Alcotest.test_case "token structure" `Quick test_csrf_token_structure;
          Alcotest.test_case "max token length" `Quick
            test_csrf_max_token_length;
          Alcotest.test_case "rand negative rejected" `Quick
            test_csrf_rand_negative;
          Alcotest.test_case "rand > uint32 rejected" `Quick
            test_csrf_rand_over_uint32;
          Alcotest.test_case "bad key encode (short)" `Quick
            test_csrf_bad_key_encode_short;
          Alcotest.test_case "bad key encode (long)" `Quick
            test_csrf_bad_key_encode_long;
          Alcotest.test_case "bad key validate (short)" `Quick
            test_csrf_bad_key_validate_short;
          Alcotest.test_case "bad key validate (long)" `Quick
            test_csrf_bad_key_validate_long;
          QCheck_alcotest.to_alcotest qcheck_csrf_roundtrip;
        ] );
      ( "Link",
        [
          Alcotest.test_case "implicit now" `Quick test_link_implicit_now;
          Alcotest.test_case "expires=0 rejected" `Quick test_link_expires_zero;
          Alcotest.test_case "expires=1441 rejected" `Quick
            test_link_expires_over_max;
          Alcotest.test_case "token structure" `Quick test_link_token_structure;
          Alcotest.test_case "bad key decode (short)" `Quick
            test_link_bad_key_decode_short;
          Alcotest.test_case "bad key decode (long)" `Quick
            test_link_bad_key_decode_long;
          Alcotest.test_case "bad yesterday key (short)" `Quick
            test_link_bad_key_yesterday_short;
          QCheck_alcotest.to_alcotest qcheck_link_roundtrip;
        ] );
      ( "Session",
        [
          Alcotest.test_case "implicit now" `Quick test_session_implicit_now;
          Alcotest.test_case "expires=0 rejected" `Quick
            test_session_expires_zero;
          Alcotest.test_case "expires=-1 rejected" `Quick
            test_session_expires_negative;
          Alcotest.test_case "expires=1441 rejected" `Quick
            test_session_expires_over_max;
          Alcotest.test_case "token structure" `Quick
            test_session_token_structure;
          Alcotest.test_case "token structure with admin" `Quick
            test_session_token_structure_with_admin;
          Alcotest.test_case "bad key decode (short)" `Quick
            test_session_bad_key_decode_short;
          Alcotest.test_case "bad key decode (long)" `Quick
            test_session_bad_key_decode_long;
          Alcotest.test_case "bad yesterday key (short)" `Quick
            test_session_bad_key_yesterday_short;
          Alcotest.test_case "issued_at overflow regression" `Quick
            test_session_issued_at_overflow;
          Alcotest.test_case "token length exactly 124" `Quick
            test_session_token_length_124;
          Alcotest.test_case "token length 125 rejected" `Quick
            test_session_token_length_125;
          QCheck_alcotest.to_alcotest qcheck_session_roundtrip;
        ] );
    ]
  in
  let suite = try Sys.getenv "BWT_TESTS" with Not_found -> "all" in
  let vector_tests =
    match suite with
    | "vectors" | "all" ->
      load_vectors ();
      [
        ( "Vectors/Meta",
          [
            Alcotest.test_case "metadata" `Quick test_vectors_metadata;
            Alcotest.test_case "keys" `Quick test_vectors_keys;
            Alcotest.test_case "known sections only" `Quick
              test_vectors_known_sections;
            Alcotest.test_case "sections non-empty" `Quick
              test_vectors_sections_nonempty;
          ] );
        "Vectors/Session", vector_session_tests ();
        "Vectors/Link", vector_link_tests ();
        "Vectors/CSRF", vector_csrf_tests ();
      ]
    | _ -> []
  in
  let tests =
    match suite with
    | "direct" -> direct_tests
    | "vectors" -> vector_tests
    | "all" -> direct_tests @ vector_tests
    | _ ->
      Printf.eprintf "Valid values for $BWT_TEST: all direct vectors\n";
      exit 1
  in
  Alcotest.run "BWT" tests
;;

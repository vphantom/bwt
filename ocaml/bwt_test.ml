let test_key = String.make 64 'K'

(** Forge a token with a valid signature but arbitrary payload. *)
let forge_token ~key payload =
  let raw =
    Digestif.SHA224.(hmac_string ~key (":" ^ payload) |> to_raw_string)
  in
  let alphabet = "GHJKLMNPQRSTVWXZ" in
  let buf = Buffer.create 80 in
  Buffer.add_string buf payload;
  Buffer.add_char buf '9';
  for i = 0 to 27 do
    let b = Char.code raw.[i] in
    Buffer.add_char buf alphabet.[b lsr 4];
    Buffer.add_char buf alphabet.[b land 0xf]
  done;
  Buffer.contents buf
;;

(* --- Utils --- *)

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
  | exception Invalid_argument _ -> ()
  | _ -> Alcotest.fail "expected Invalid_argument"
;;

let pp_invalid fmt = function
  | Bwt.Bad_admin -> Fmt.string fmt "Bad_admin"
  | Bwt.Bad_expiry -> Fmt.string fmt "Bad_expiry"
  | Bwt.Bad_issue -> Fmt.string fmt "Bad_issue"
  | Bwt.Bad_signature -> Fmt.string fmt "Bad_signature"
  | Bwt.Bad_user -> Fmt.string fmt "Bad_user"
  | Bwt.Expired -> Fmt.string fmt "Expired"
  | Bwt.Future -> Fmt.string fmt "Future"
  | Bwt.Int_overflow -> Fmt.string fmt "Int_overflow"
  | Bwt.Malformed -> Fmt.string fmt "Malformed"
;;

let invalid_t = Alcotest.testable pp_invalid ( = )

let pp_form fmt = function
  | Bwt.Short -> Fmt.string fmt "Short"
  | Bwt.Full -> Fmt.string fmt "Full"
;;

let form_t = Alcotest.testable pp_form ( = )

let expect_error e = function
  | Error e' when e = e' -> ()
  | Error e' ->
    Alcotest.failf "got error %a, expected %a" pp_invalid e' pp_invalid e
  | Ok _ -> Alcotest.failf "got ok, expected error %a" pp_invalid e
;;

let expect_ok = function
  | Ok _ -> ()
  | Error e -> Alcotest.failf "got error %a" pp_invalid e
;;

let ( let* ) v f =
  match v with
  | Ok v -> f v
  | Error e -> Alcotest.failf "got error %a" pp_invalid e
;;

let test_int_of_safehex_known_values () =
  Alcotest.(check (result int invalid_t)) "G" (Ok 0) (Bwt.int_of_safehex "G");
  Alcotest.(check (result int invalid_t)) "H" (Ok 1) (Bwt.int_of_safehex "H");
  Alcotest.(check (result int invalid_t)) "Z" (Ok 15) (Bwt.int_of_safehex "Z");
  Alcotest.(check (result int invalid_t)) "HG" (Ok 16) (Bwt.int_of_safehex "HG");
  Alcotest.(check (result int invalid_t)) "ZZ" (Ok 255) (Bwt.int_of_safehex "ZZ");
  Alcotest.(check (result int invalid_t))
    "HGG" (Ok 256) (Bwt.int_of_safehex "HGG")
;;

let test_int_of_safehex_empty () =
  Alcotest.(check (result int invalid_t))
    "empty" (Error Bwt.Malformed) (Bwt.int_of_safehex "")
;;

let test_int_of_safehex_invalid () =
  Alcotest.(check (result int invalid_t))
    "lowercase" (Error Malformed) (Bwt.int_of_safehex "g");
  Alcotest.(check (result int invalid_t))
    "digit" (Error Malformed) (Bwt.int_of_safehex "0");
  Alcotest.(check (result int invalid_t))
    "hex letter" (Error Malformed) (Bwt.int_of_safehex "A");
  Alcotest.(check (result int invalid_t))
    "mixed valid/invalid" (Error Malformed) (Bwt.int_of_safehex "GA");
  Alcotest.(check (result int invalid_t))
    "leading zero" (Error Malformed) (Bwt.int_of_safehex "GG");
  Alcotest.(check (result int invalid_t))
    "17 chars overflow" (Error Int_overflow)
    (Bwt.int_of_safehex "HHGGGGGGGGGGGGGGG");
  Alcotest.(check (result int invalid_t))
    "2^62 overflow" (Error Int_overflow)
    (Bwt.int_of_safehex "LGGGGGGGGGGGGGGG");
  Alcotest.(check (result int invalid_t))
    "max_int accepted" (Ok max_int)
    (Bwt.int_of_safehex "KZZZZZZZZZZZZZZZ")
;;

let qcheck_safehex_roundtrip =
  QCheck.Test.make ~name:"safehex round-trip" ~count:10_000
    QCheck.(int_range 0 max_int)
    (fun n -> Bwt.int_of_safehex (Bwt.safehex_of_int n) = Ok n)
;;

(* --- Encode --- *)

let test_make_negative_issued_at () =
  expect_error Bwt.Int_overflow @@ Bwt.make ~issued_at:(-1) ~user:0 30
;;

let test_make_zero_expires () =
  expect_error Bwt.Bad_expiry @@ Bwt.make ~user:0 0
;;

let test_make_negative_expires () =
  expect_error Bwt.Bad_expiry @@ Bwt.make ~user:0 (-5)
;;

let test_make_is_stale_false () =
  let* t = Bwt.make ~user:0 100 in
  Alcotest.(check bool) "fresh token not stale" false t.is_stale
;;

let test_make_is_stale_true () =
  let issued = Unix.time () -. 3000.0 |> int_of_float in
  let* t = Bwt.make ~issued_at:issued ~user:0 100 in
  Alcotest.(check bool) "50min into 100min is stale" true t.is_stale
;;

let test_encode_rejects_bad_key_length () =
  let* t = Bwt.make ~user:0 30 in
  ( match Bwt.encode ~today:(String.make 63 'K') t with
  | exception Invalid_argument _ -> ()
  | _ -> Alcotest.fail "expected Invalid_argument for short key"
  );
  match Bwt.encode ~today:(String.make 129 'K') t with
  | exception Invalid_argument _ -> ()
  | _ -> Alcotest.fail "expected Invalid_argument for long key"
;;

let test_encode_nonempty () =
  let* t = Bwt.make ~user:0 30 in
  let s = Bwt.encode ~today:test_key t in
  Alcotest.(check bool) "non-empty" true (String.length s > 0)
;;

(* --- Decode --- *)

let test_decode_roundtrip_minimal () =
  let* t = Bwt.make ~user:0 30 in
  let s = Bwt.encode ~today:test_key t in
  let* d = Bwt.decode ~today:test_key s in
  Alcotest.(check int) "issued_at" t.issued_at d.issued_at;
  Alcotest.(check int) "expires" t.expires d.expires;
  Alcotest.(check int) "user" t.user d.user;
  Alcotest.(check (option int)) "admin" None d.admin;
  Alcotest.(check form_t) "form" Bwt.Full d.form
;;

let test_decode_roundtrip_user_only () =
  let* t = Bwt.make ~user:1000 30 in
  let s = Bwt.encode ~today:test_key t in
  let* d = Bwt.decode ~today:test_key s in
  Alcotest.(check int) "user" 1000 d.user;
  Alcotest.(check (option int)) "admin" None d.admin
;;

let test_decode_roundtrip_full () =
  let* t = Bwt.make ~form:Short ~user:42 ~admin:7 720 in
  let s = Bwt.encode ~today:test_key t in
  let* d = Bwt.decode ~form:Short ~today:test_key s in
  Alcotest.(check int) "issued_at" t.issued_at d.issued_at;
  Alcotest.(check int) "expires" t.expires d.expires;
  Alcotest.(check int) "user" 42 d.user;
  Alcotest.(check (option int)) "admin" (Some 7) d.admin;
  Alcotest.(check form_t) "form" Bwt.Short d.form
;;

let test_decode_wrong_key () =
  let* t = Bwt.make ~user:0 30 in
  let s = Bwt.encode ~today:test_key t in
  let bad_key = String.make 64 'X' in
  expect_error Bwt.Bad_signature @@ Bwt.decode ~today:bad_key s
;;

let test_decode_yesterday_fallback () =
  let old_key = String.make 64 'Y' in
  let* t = Bwt.make ~user:0 30 in
  let s = Bwt.encode ~today:old_key t in
  let* d = Bwt.decode ~yesterday:old_key ~today:test_key s in
  Alcotest.(check int) "expires" 30 d.expires
;;

let test_decode_malformed () =
  let check s msg =
    Alcotest.(check bool)
      msg true
      (Result.is_error (Bwt.decode ~today:test_key s))
  in
  check "" "empty string";
  check "not-a-token" "garbage";
  check "GG5GG" "no signature separator";
  check "GG9" "empty signature";
  check "9GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG" "empty payload"
;;

let test_decode_payload_too_few_fields () =
  let check payload msg =
    let s = forge_token ~key:test_key payload in
    Alcotest.(check bool)
      msg true
      (Result.is_error (Bwt.decode ~today:test_key s))
  in
  check "" "zero fields rejected";
  check "G" "one field rejected"
;;

let test_decode_payload_too_many_fields () =
  let s = forge_token ~key:test_key "G5G5G5G5G" in
  Alcotest.(check bool)
    "five fields rejected" true
    (Result.is_error (Bwt.decode ~today:test_key s))
;;

let test_decode_both_keys_invalid () =
  let* t = Bwt.make ~user:0 30 in
  let s = Bwt.encode ~today:test_key t in
  let bad1 = String.make 64 'X' in
  let bad2 = String.make 64 'Y' in
  expect_error Bwt.Bad_signature @@ Bwt.decode ~yesterday:bad2 ~today:bad1 s
;;

let test_decode_stale_flag () =
  let issued = Unix.time () -. 3000.0 |> int_of_float in
  let* t = Bwt.make ~issued_at:issued ~user:0 100 in
  let s = Bwt.encode ~today:test_key t in
  let* d = Bwt.decode ~today:test_key s in
  Alcotest.(check bool) "is_stale" true d.is_stale
;;

let qcheck_encode_decode_roundtrip =
  QCheck.Test.make ~name:"encode/decode round-trip" ~count:1_000
    QCheck.(quad nat_small (option nat_small) bool (int_range 1 1440))
    (fun (user, admin, is_short, expires) ->
      let form = if is_short then Bwt.Short else Bwt.Full in
      let* t = Bwt.make ~form ~user ?admin expires in
      let s = Bwt.encode ~today:test_key t in
      let* d = Bwt.decode ~form ~today:test_key s in
      d.issued_at = t.issued_at
      && d.expires = t.expires
      && d.user = t.user
      && d.admin = t.admin
      && d.form = t.form
    )
;;

let () =
  Alcotest.run "BWT"
    [
      ( "Utils",
        [
          Alcotest.test_case "safehex_of_int zero" `Quick
            test_safehex_of_int_zero;
          Alcotest.test_case "safehex_of_int known values" `Quick
            test_safehex_of_int_known_values;
          Alcotest.test_case "safehex_of_int negative" `Quick
            test_safehex_of_int_negative;
          Alcotest.test_case "int_of_safehex known values" `Quick
            test_int_of_safehex_known_values;
          Alcotest.test_case "int_of_safehex empty" `Quick
            test_int_of_safehex_empty;
          Alcotest.test_case "int_of_safehex invalid" `Quick
            test_int_of_safehex_invalid;
          QCheck_alcotest.to_alcotest qcheck_safehex_roundtrip;
        ] );
      ( "Encode",
        [
          Alcotest.test_case "make rejects negative issued_at" `Quick
            test_make_negative_issued_at;
          Alcotest.test_case "make rejects zero expires" `Quick
            test_make_zero_expires;
          Alcotest.test_case "make rejects negative expires" `Quick
            test_make_negative_expires;
          Alcotest.test_case "make is_stale false when fresh" `Quick
            test_make_is_stale_false;
          Alcotest.test_case "make is_stale true at 50%" `Quick
            test_make_is_stale_true;
          Alcotest.test_case "encode rejects bad key length" `Quick
            test_encode_rejects_bad_key_length;
          Alcotest.test_case "encode produces output" `Quick
            test_encode_nonempty;
        ] );
      ( "Decode",
        [
          Alcotest.test_case "round-trip minimal" `Quick
            test_decode_roundtrip_minimal;
          Alcotest.test_case "round-trip user only" `Quick
            test_decode_roundtrip_user_only;
          Alcotest.test_case "round-trip full" `Quick test_decode_roundtrip_full;
          Alcotest.test_case "wrong key rejected" `Quick test_decode_wrong_key;
          Alcotest.test_case "yesterday fallback" `Quick
            test_decode_yesterday_fallback;
          Alcotest.test_case "malformed inputs" `Quick test_decode_malformed;
          Alcotest.test_case "too few payload fields" `Quick
            test_decode_payload_too_few_fields;
          Alcotest.test_case "too many payload fields" `Quick
            test_decode_payload_too_many_fields;
          Alcotest.test_case "both keys invalid" `Quick
            test_decode_both_keys_invalid;
          Alcotest.test_case "stale flag on decode" `Quick
            test_decode_stale_flag;
          QCheck_alcotest.to_alcotest qcheck_encode_decode_roundtrip;
        ] );
    ]
;;

let test_key = String.make 64 'K'

(** Forge a token with a valid signature but arbitrary payload. *)
let forge_token ~key payload =
  let raw = Digestif.SHA224.(hmac_string ~key payload |> to_raw_string) in
  let alphabet = "GHJKLMNPQRSTVWXZ" in
  let buf = Buffer.create 80 in
  Buffer.add_string buf payload;
  Buffer.add_char buf '6';
  for i = 0 to 15 do
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

let test_int_of_safehex_known_values () =
  Alcotest.(check (option int)) "G" (Some 0) (Bwt.int_of_safehex "G");
  Alcotest.(check (option int)) "H" (Some 1) (Bwt.int_of_safehex "H");
  Alcotest.(check (option int)) "Z" (Some 15) (Bwt.int_of_safehex "Z");
  Alcotest.(check (option int)) "HG" (Some 16) (Bwt.int_of_safehex "HG");
  Alcotest.(check (option int)) "ZZ" (Some 255) (Bwt.int_of_safehex "ZZ");
  Alcotest.(check (option int)) "HGG" (Some 256) (Bwt.int_of_safehex "HGG")
;;

let test_int_of_safehex_empty () =
  Alcotest.(check (option int)) "empty" None (Bwt.int_of_safehex "")
;;

let test_int_of_safehex_invalid () =
  Alcotest.(check (option int)) "lowercase" None (Bwt.int_of_safehex "g");
  Alcotest.(check (option int)) "digit" None (Bwt.int_of_safehex "0");
  Alcotest.(check (option int)) "hex letter" None (Bwt.int_of_safehex "A");
  Alcotest.(check (option int))
    "mixed valid/invalid" None (Bwt.int_of_safehex "GA")
;;

let qcheck_safehex_roundtrip =
  QCheck.Test.make ~name:"safehex round-trip" ~count:10_000
    QCheck.(int_range 0 max_int)
    (fun n -> Bwt.int_of_safehex (Bwt.safehex_of_int n) = Some n)
;;

let test_random_key_length () =
  Alcotest.(check int) "64 bytes" 64 (String.length (Bwt.random_key ()))
;;

let test_random_key_uniqueness () =
  let k1 = Bwt.random_key () in
  let k2 = Bwt.random_key () in
  Alcotest.(check bool) "two keys differ" true (k1 <> k2)
;;

(* --- Encode --- *)

let test_make_negative_issued_at () =
  match Bwt.make ~issued_at:(-1.0) 30 with
  | exception Invalid_argument _ -> ()
  | _ -> Alcotest.fail "expected Invalid_argument"
;;

let test_make_zero_expires () =
  match Bwt.make 0 with
  | exception Invalid_argument _ -> ()
  | _ -> Alcotest.fail "expected Invalid_argument"
;;

let test_make_negative_expires () =
  match Bwt.make (-5) with
  | exception Invalid_argument _ -> ()
  | _ -> Alcotest.fail "expected Invalid_argument"
;;

let test_make_admin_without_user () =
  match Bwt.make ~admin:1 30 with
  | exception Invalid_argument _ -> ()
  | _ -> Alcotest.fail "expected Invalid_argument"
;;

let test_make_is_stale_false () =
  let t = Bwt.make ~issued_at:(Unix.gettimeofday ()) 100 in
  Alcotest.(check bool) "fresh token not stale" false t.is_stale
;;

let test_make_is_stale_true () =
  let issued = Unix.gettimeofday () -. 3000.0 in
  let t = Bwt.make ~issued_at:issued 100 in
  Alcotest.(check bool) "50min into 100min is stale" true t.is_stale
;;

let test_encode_str_nonempty () =
  let t = Bwt.make 30 in
  let s = Bwt.encode_str ~today:test_key t in
  Alcotest.(check bool) "non-empty" true (String.length s > 0)
;;

(* --- Decode --- *)

let test_decode_roundtrip_minimal () =
  let t = Bwt.make ~issued_at:(Unix.gettimeofday ()) 30 in
  let s = Bwt.encode_str ~today:test_key t in
  match Bwt.decode ~today:test_key s with
  | None -> Alcotest.fail "decode returned None"
  | Some d ->
    Alcotest.(check int) "issued_at" t.issued_at d.issued_at;
    Alcotest.(check int) "expires" t.expires d.expires;
    Alcotest.(check (option int)) "user" None d.user;
    Alcotest.(check (option int)) "admin" None d.admin;
    Alcotest.(check bool) "is_nonce" false d.is_nonce
;;

let test_decode_roundtrip_user_only () =
  let t = Bwt.make ~issued_at:(Unix.gettimeofday ()) ~user:1000 30 in
  let s = Bwt.encode_str ~today:test_key t in
  match Bwt.decode ~today:test_key s with
  | None -> Alcotest.fail "decode returned None"
  | Some d ->
    Alcotest.(check (option int)) "user" (Some 1000) d.user;
    Alcotest.(check (option int)) "admin" None d.admin
;;

let test_decode_roundtrip_full () =
  let t =
    Bwt.make ~issued_at:(Unix.gettimeofday ()) ~user:42 ~admin:7 ~nonce:true 720
  in
  let s = Bwt.encode_str ~today:test_key t in
  match Bwt.decode ~today:test_key s with
  | None -> Alcotest.fail "decode returned None"
  | Some d ->
    Alcotest.(check int) "issued_at" t.issued_at d.issued_at;
    Alcotest.(check int) "expires" t.expires d.expires;
    Alcotest.(check (option int)) "user" (Some 42) d.user;
    Alcotest.(check (option int)) "admin" (Some 7) d.admin;
    Alcotest.(check bool) "is_nonce" true d.is_nonce
;;

let test_decode_wrong_key () =
  let t = Bwt.make 30 in
  let s = Bwt.encode_str ~today:test_key t in
  let bad_key = String.make 64 'X' in
  Alcotest.(check bool)
    "wrong key -> None" true
    (Option.is_none (Bwt.decode ~today:bad_key s))
;;

let test_decode_yesterday_fallback () =
  let old_key = String.make 64 'Y' in
  let t = Bwt.make ~issued_at:(Unix.gettimeofday ()) 30 in
  let s = Bwt.encode_str ~today:old_key t in
  match Bwt.decode ~yesterday:old_key ~today:test_key s with
  | None -> Alcotest.fail "yesterday fallback failed"
  | Some d -> Alcotest.(check int) "expires" 30 d.expires
;;

let test_decode_malformed () =
  let check s msg =
    Alcotest.(check bool)
      msg true
      (Option.is_none (Bwt.decode ~today:test_key s))
  in
  check "" "empty string";
  check "not-a-token" "garbage";
  check "GG5GG" "no signature separator";
  check "GG6" "empty signature";
  check "6GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG" "empty payload"
;;

let test_decode_payload_too_few_fields () =
  let check payload msg =
    let s = forge_token ~key:test_key payload in
    Alcotest.(check bool)
      msg true
      (Option.is_none (Bwt.decode ~today:test_key s))
  in
  check "" "zero fields rejected";
  check "G" "one field rejected"
;;

let test_decode_payload_too_many_fields () =
  let s = forge_token ~key:test_key "G5G5G5G5G" in
  Alcotest.(check bool)
    "five fields rejected" true
    (Option.is_none (Bwt.decode ~today:test_key s))
;;

let test_decode_both_keys_invalid () =
  let t = Bwt.make 30 in
  let s = Bwt.encode_str ~today:test_key t in
  let bad1 = String.make 64 'X' in
  let bad2 = String.make 64 'Y' in
  Alcotest.(check bool)
    "both keys rejected" true
    (Option.is_none (Bwt.decode ~yesterday:bad2 ~today:bad1 s))
;;

let test_decode_stale_flag () =
  let issued = Unix.gettimeofday () -. 3000.0 in
  let t = Bwt.make ~issued_at:issued 100 in
  let s = Bwt.encode_str ~today:test_key t in
  match Bwt.decode ~today:test_key s with
  | None -> Alcotest.fail "decode returned None"
  | Some d -> Alcotest.(check bool) "is_stale" true d.is_stale
;;

let qcheck_encode_decode_roundtrip =
  QCheck.Test.make ~name:"encode/decode round-trip" ~count:1_000
    QCheck.(quad (option nat_small) (option nat_small) bool (int_range 1 1440))
    (fun (user, admin, nonce, expires) ->
      QCheck.assume (expires >= 1);
      QCheck.assume (Option.is_none admin || Option.is_some user);
      let t = Bwt.make ?user ?admin ~nonce expires in
      let s = Bwt.encode_str ~today:test_key t in
      match Bwt.decode ~today:test_key s with
      | None -> false
      | Some d ->
        d.issued_at = t.issued_at
        && d.expires = t.expires
        && d.user = t.user
        && d.admin = t.admin
        && d.is_nonce = t.is_nonce
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
          Alcotest.test_case "random_key length" `Quick test_random_key_length;
          Alcotest.test_case "random_key uniqueness" `Quick
            test_random_key_uniqueness;
        ] );
      ( "Encode",
        [
          Alcotest.test_case "make rejects negative issued_at" `Quick
            test_make_negative_issued_at;
          Alcotest.test_case "make rejects zero expires" `Quick
            test_make_zero_expires;
          Alcotest.test_case "make rejects negative expires" `Quick
            test_make_negative_expires;
          Alcotest.test_case "make rejects admin without user" `Quick
            test_make_admin_without_user;
          Alcotest.test_case "make is_stale false when fresh" `Quick
            test_make_is_stale_false;
          Alcotest.test_case "make is_stale true at 50%" `Quick
            test_make_is_stale_true;
          Alcotest.test_case "encode_str produces output" `Quick
            test_encode_str_nonempty;
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

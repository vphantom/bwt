(** Generate test-vectors.json for cross-implementation testing

    Usage: dune exec ocaml/bwt_vectors.exe > test-vectors.json

    This program generates deterministic test vectors from known inputs using
    the OCaml BWT implementation as the reference. Other implementations consume
    the resulting JSON to verify encoding, decoding, and validation
    compatibility.

    Each positive vector checks three things: 1. Encoding the given inputs
    produces expected_token exactly. 2. Decoding expected_token succeeds with
    the correct field values. 3. Validating the decoded token returns the
    expected result.

    Negative vectors assert failure at the indicated stage; error messages are
    implementation-specific and not checked. *)

(* --- Standard hex encoding --- *)

let hex_of_string s =
  let buf = Buffer.create (String.length s * 2) in
  String.iter (fun c -> Printf.bprintf buf "%02x" (Char.code c)) s;
  Buffer.contents buf
;;

(* --- Fixed test parameters --- *)

let bwt_epoch = 1_750_750_750
let fixed_now = bwt_epoch + 10_000_000

(* Keys must be 64–128 bytes. *)
let key_today = String.make 64 'T'
let key_yesterday = String.make 64 'Y'

(* --- Helpers --- *)

let unwrap = function
  | Ok v -> v
  | Error e -> failwith ("vector generation failed: " ^ e)
;;

let int_or_null = function
  | None -> `Null
  | Some i -> `Int i
;;

let string_or_null = function
  | None -> `Null
  | Some s -> `String s
;;

let key_of_name = function
  | "today" -> key_today
  | "yesterday" -> key_yesterday
  | s -> failwith ("unknown key name: " ^ s)
;;

(** Replace the last character with a non-safe-hex character. *)
let corrupt_sig s =
  let b = Bytes.of_string s in
  Bytes.set b (String.length s - 1) 'a';
  Bytes.to_string b
;;

(** Flip one safe-hex character at position [i] in [s]. *)
let tamper s i =
  let b = Bytes.of_string s in
  Bytes.set b i (if Bytes.get b i = 'H' then 'J' else 'H');
  Bytes.to_string b
;;

(** Forge a Session token: sign [payload] with [key_today] and [salt] using
    Session's separator [:] and full 56-char safe-hex signature. *)
let forge_session ~salt payload =
  let hmac_input = salt ^ ":" ^ payload in
  let raw_sig =
    Digestif.SHA224.(hmac_string ~key:key_today hmac_input |> to_raw_string)
  in
  let sig_hex = Bwt.safehex_of_string raw_sig in
  payload ^ "9" ^ String.sub sig_hex 0 56
;;

(** Forge a Link token: sign [payload] with [key_today] and [action] using
    Link's separator [=] and truncated 32-char safe-hex signature. *)
let forge_link ~action payload =
  let hmac_input = action ^ "=" ^ payload in
  let raw_sig =
    Digestif.SHA224.(hmac_string ~key:key_today hmac_input |> to_raw_string)
  in
  let sig_hex = Bwt.safehex_of_string raw_sig in
  payload ^ "9" ^ String.sub sig_hex 0 32
;;

(* ===== Positive Session Vectors ===== *)

let session_positive ~name ~key_name ~salt ~now ~user_id ?admin_id ~expires
  ~validate_now ~logout_at ?admin_logout_at expected_result =
  let key = key_of_name key_name in
  let tok =
    Bwt.Session.encode ~key ~now ~salt ~user_id ?admin_id expires |> unwrap
  in
  let decode_yesterday =
    match key_name with
    | "yesterday" -> Some "yesterday"
    | _ -> None
  in
  `Assoc
    [
      "name", `String name;
      ( "encode",
        `Assoc
          [
            "key", `String key_name;
            "salt", `String salt;
            "now", `Int now;
            "user_id", `Int user_id;
            "admin_id", int_or_null admin_id;
            "expires", `Int expires;
          ] );
      "expected_token", `String tok;
      ( "decode",
        `Assoc
          [
            "today", `String "today";
            "yesterday", string_or_null decode_yesterday;
            "salt", `String salt;
          ] );
      ( "validate",
        `Assoc
          [
            "now", `Int validate_now;
            "logout_at", `Int logout_at;
            "admin_logout_at", int_or_null admin_logout_at;
            "expected", `String expected_result;
          ] );
    ]
;;

let session_positives () =
  [
    session_positive ~name:"no admin, empty salt, expires=60" ~key_name:"today"
      ~salt:"" ~now:fixed_now ~user_id:1 ~expires:60 ~validate_now:fixed_now
      ~logout_at:0 "fresh";
    session_positive ~name:"with admin, empty salt" ~key_name:"today" ~salt:""
      ~now:fixed_now ~user_id:1 ~admin_id:99 ~expires:60 ~validate_now:fixed_now
      ~logout_at:0 ~admin_logout_at:0 "fresh";
    session_positive ~name:"non-empty salt (session)" ~key_name:"today"
      ~salt:"session" ~now:fixed_now ~user_id:1 ~expires:60
      ~validate_now:fixed_now ~logout_at:0 "fresh";
    session_positive ~name:"expires=1 (minimum)" ~key_name:"today" ~salt:""
      ~now:fixed_now ~user_id:1 ~expires:1 ~validate_now:fixed_now ~logout_at:0
      "fresh";
    session_positive ~name:"expires=1440 (maximum)" ~key_name:"today" ~salt:""
      ~now:fixed_now ~user_id:1 ~expires:1440 ~validate_now:fixed_now
      ~logout_at:0 "fresh";
    session_positive ~name:"yesterday key (decode with both)"
      ~key_name:"yesterday" ~salt:"" ~now:fixed_now ~user_id:1 ~expires:60
      ~validate_now:fixed_now ~logout_at:0 "fresh";
    session_positive ~name:"stale (20% of 10 min elapsed)" ~key_name:"today"
      ~salt:"" ~now:fixed_now ~user_id:1 ~expires:10
      ~validate_now:(fixed_now + 120) ~logout_at:0 "stale";
    session_positive ~name:"large user_id" ~key_name:"today" ~salt:""
      ~now:fixed_now ~user_id:1_000_000 ~expires:60 ~validate_now:fixed_now
      ~logout_at:0 "fresh";
    session_positive ~name:"expiry boundary at 599s (valid stale)"
      ~key_name:"today" ~salt:"" ~now:fixed_now ~user_id:1 ~expires:10
      ~validate_now:(fixed_now + 599) ~logout_at:0 "stale";
    session_positive ~name:"freshness boundary at 119s (fresh)"
      ~key_name:"today" ~salt:"" ~now:fixed_now ~user_id:1 ~expires:10
      ~validate_now:(fixed_now + 119) ~logout_at:0 "fresh";
    session_positive ~name:"future within 5s skew (fresh)" ~key_name:"today"
      ~salt:"" ~now:(fixed_now + 5) ~user_id:1 ~expires:60
      ~validate_now:fixed_now ~logout_at:0 "fresh";
  ]
;;

(* ===== Positive Link Vectors ===== *)

let link_positive ~name ~key_name ~action ~now ~user_id ~expires ~validate_now
  ~last_nonce_at expected_result =
  let key = key_of_name key_name in
  let tok = Bwt.Link.encode ~key ~now ~action ~user_id expires |> unwrap in
  let decode_yesterday =
    match key_name with
    | "yesterday" -> Some "yesterday"
    | _ -> None
  in
  `Assoc
    [
      "name", `String name;
      ( "encode",
        `Assoc
          [
            "key", `String key_name;
            "action", `String action;
            "now", `Int now;
            "user_id", `Int user_id;
            "expires", `Int expires;
          ] );
      "expected_token", `String tok;
      ( "decode",
        `Assoc
          [
            "today", `String "today";
            "yesterday", string_or_null decode_yesterday;
            "action", `String action;
          ] );
      ( "validate",
        `Assoc
          [
            "now", `Int validate_now;
            "last_nonce_at", `Int last_nonce_at;
            "expected", `String expected_result;
          ] );
    ]
;;

let link_positives () =
  [
    link_positive ~name:"action=login, expires=60" ~key_name:"today"
      ~action:"login" ~now:fixed_now ~user_id:1 ~expires:60
      ~validate_now:fixed_now ~last_nonce_at:0 "valid";
    link_positive ~name:"action=password-reset, expires=1" ~key_name:"today"
      ~action:"password-reset" ~now:fixed_now ~user_id:1 ~expires:1
      ~validate_now:fixed_now ~last_nonce_at:0 "valid";
    link_positive ~name:"expires=1440 (maximum)" ~key_name:"today"
      ~action:"login" ~now:fixed_now ~user_id:1 ~expires:1440
      ~validate_now:fixed_now ~last_nonce_at:0 "valid";
    link_positive ~name:"yesterday key (decode with both)" ~key_name:"yesterday"
      ~action:"login" ~now:fixed_now ~user_id:1 ~expires:60
      ~validate_now:fixed_now ~last_nonce_at:0 "valid";
    link_positive ~name:"expiry boundary at 599s (valid)" ~key_name:"today"
      ~action:"login" ~now:fixed_now ~user_id:1 ~expires:10
      ~validate_now:(fixed_now + 599) ~last_nonce_at:0 "valid";
    link_positive ~name:"future within 5s skew (valid)" ~key_name:"today"
      ~action:"login" ~now:(fixed_now + 5) ~user_id:1 ~expires:60
      ~validate_now:fixed_now ~last_nonce_at:0 "valid";
    link_positive ~name:"nonce just before issued_at (valid)" ~key_name:"today"
      ~action:"login" ~now:fixed_now ~user_id:1 ~expires:60
      ~validate_now:fixed_now ~last_nonce_at:(fixed_now - 1) "valid";
  ]
;;

(* ===== Positive CSRF Vectors ===== *)

let csrf_positive ~name ~key_name ~rand ~user_id ~form_id ~validate_today
  ?validate_yesterday ~validate_form_id ~validate_user_id expected_result =
  let key = key_of_name key_name in
  let tok = Bwt.CSRF.encode ~key ~rand ~user_id form_id |> unwrap in
  `Assoc
    [
      "name", `String name;
      ( "encode",
        `Assoc
          [
            "key", `String key_name;
            "rand", `Int rand;
            "user_id", `Int user_id;
            "form_id", `String form_id;
          ] );
      "expected_token", `String tok;
      ( "validate",
        `Assoc
          [
            "today", `String validate_today;
            "yesterday", string_or_null validate_yesterday;
            "form_id", `String validate_form_id;
            "user_id", `Int validate_user_id;
            "expected", `String expected_result;
          ] );
    ]
;;

let csrf_positives () =
  [
    csrf_positive ~name:"rand=0 (minimum)" ~key_name:"today" ~rand:0 ~user_id:1
      ~form_id:"login" ~validate_today:"today" ~validate_form_id:"login"
      ~validate_user_id:1 "valid";
    csrf_positive ~name:"rand=4294967295 (max uint32)" ~key_name:"today"
      ~rand:4_294_967_295 ~user_id:1 ~form_id:"login" ~validate_today:"today"
      ~validate_form_id:"login" ~validate_user_id:1 "valid";
    csrf_positive ~name:"typical (rand=42)" ~key_name:"today" ~rand:42
      ~user_id:1 ~form_id:"login" ~validate_today:"today"
      ~validate_form_id:"login" ~validate_user_id:1 "valid";
    csrf_positive ~name:"yesterday key" ~key_name:"yesterday" ~rand:42
      ~user_id:1 ~form_id:"login" ~validate_today:"today"
      ~validate_yesterday:"yesterday" ~validate_form_id:"login"
      ~validate_user_id:1 "valid";
  ]
;;

(* ===== Negative Vectors ===== *)

(** Helpers to reduce repetition in negative vector construction.
    "should_fail_at" is "decode" or "validate". For "decode": the test calls
    decode and expects an error. For "validate": the test first decodes
    (expecting success) then validates with the given parameters and expects an
    error. *)

let neg_session_decode ~name token ~salt =
  `Assoc
    [
      "name", `String name;
      "token", `String token;
      "should_fail_at", `String "decode";
      ( "decode",
        `Assoc
          [ "today", `String "today"; "yesterday", `Null; "salt", `String salt ]
      );
    ]
;;

let neg_session_validate ~name token ~salt ~now ~logout_at ?admin_logout_at () =
  `Assoc
    [
      "name", `String name;
      "token", `String token;
      "should_fail_at", `String "validate";
      ( "decode",
        `Assoc
          [ "today", `String "today"; "yesterday", `Null; "salt", `String salt ]
      );
      ( "validate",
        `Assoc
          [
            "now", `Int now;
            "logout_at", `Int logout_at;
            "admin_logout_at", int_or_null admin_logout_at;
          ] );
    ]
;;

let neg_link_decode ~name token ~action =
  `Assoc
    [
      "name", `String name;
      "token", `String token;
      "should_fail_at", `String "decode";
      ( "decode",
        `Assoc
          [
            "today", `String "today";
            "yesterday", `Null;
            "action", `String action;
          ] );
    ]
;;

let neg_link_validate ~name token ~action ~now ~last_nonce_at =
  `Assoc
    [
      "name", `String name;
      "token", `String token;
      "should_fail_at", `String "validate";
      ( "decode",
        `Assoc
          [
            "today", `String "today";
            "yesterday", `Null;
            "action", `String action;
          ] );
      ( "validate",
        `Assoc [ "now", `Int now; "last_nonce_at", `Int last_nonce_at ] );
    ]
;;

let neg_csrf ~name token ~form_id ~user_id =
  `Assoc
    [
      "name", `String name;
      "token", `String token;
      "should_fail_at", `String "validate";
      ( "validate",
        `Assoc
          [
            "today", `String "today";
            "yesterday", `Null;
            "form_id", `String form_id;
            "user_id", `Int user_id;
          ] );
    ]
;;

(* Reference tokens for cross-form and tampering tests *)

let session_tok =
  Bwt.Session.encode ~key:key_today ~now:fixed_now ~user_id:1 60 |> unwrap
;;

let session_admin_tok =
  Bwt.Session.encode ~key:key_today ~now:fixed_now ~user_id:1 ~admin_id:99 60
  |> unwrap
;;

let session_salt_tok =
  Bwt.Session.encode ~key:key_today ~now:fixed_now ~salt:"session" ~user_id:1 60
  |> unwrap
;;

let session_10min_tok =
  Bwt.Session.encode ~key:key_today ~now:fixed_now ~user_id:1 10 |> unwrap
;;

let session_future_tok =
  Bwt.Session.encode ~key:key_today ~now:(fixed_now + 10) ~user_id:1 60
  |> unwrap
;;

let link_tok =
  Bwt.Link.encode ~key:key_today ~now:fixed_now ~action:"login" ~user_id:1 60
  |> unwrap
;;

let link_10min_tok =
  Bwt.Link.encode ~key:key_today ~now:fixed_now ~action:"login" ~user_id:1 10
  |> unwrap
;;

let link_future_tok =
  Bwt.Link.encode ~key:key_today ~now:(fixed_now + 10) ~action:"login"
    ~user_id:1 60
  |> unwrap
;;

let csrf_tok =
  Bwt.CSRF.encode ~key:key_today ~rand:42 ~user_id:1 "login" |> unwrap
;;

let session_future6_tok =
  Bwt.Session.encode ~key:key_today ~now:(fixed_now + 6) ~user_id:1 60 |> unwrap
;;

let session_yesterday_tok =
  Bwt.Session.encode ~key:key_yesterday ~now:fixed_now ~user_id:1 60 |> unwrap
;;

let link_future6_tok =
  Bwt.Link.encode ~key:key_today ~now:(fixed_now + 6) ~action:"login" ~user_id:1
    60
  |> unwrap
;;

let link_yesterday_tok =
  Bwt.Link.encode ~key:key_yesterday ~now:fixed_now ~action:"login" ~user_id:1
    60
  |> unwrap
;;

let csrf_yesterday_tok =
  Bwt.CSRF.encode ~key:key_yesterday ~rand:42 ~user_id:1 "login" |> unwrap
;;

let session_negatives () =
  [
    neg_session_decode ~name:"link token in session decoder" link_tok ~salt:"";
    neg_session_decode ~name:"CSRF token in session decoder" csrf_tok ~salt:"";
    neg_session_decode ~name:"session: tampered payload" (tamper session_tok 0)
      ~salt:"";
    neg_session_decode ~name:"session: tampered signature"
      (tamper session_tok (String.length session_tok - 1))
      ~salt:"";
    neg_session_decode ~name:"session: invalid char in signature"
      (corrupt_sig session_tok) ~salt:"";
    neg_session_decode ~name:"session: no separator" (String.make 62 'H')
      ~salt:"";
    neg_session_decode ~name:"session: multiple separators"
      ("H5H5H9H5H5H9" ^ String.make 56 'H')
      ~salt:"";
    neg_session_decode ~name:"session: forged empty field"
      (forge_session ~salt:"" "H55H5H")
      ~salt:"";
    neg_session_decode ~name:"session: forged leading zero"
      (forge_session ~salt:"" "GH5H5H")
      ~salt:"";
    neg_session_decode ~name:"session: forged field too long"
      (forge_session ~salt:"" "HHGGGGGGGGGGGGGGG5H5H")
      ~salt:"";
    neg_session_decode ~name:"session: forged invalid char in payload"
      (forge_session ~salt:"" "A5H5H")
      ~salt:"";
    neg_session_decode ~name:"session: forged too few fields"
      (forge_session ~salt:"" "H5H")
      ~salt:"";
    neg_session_decode ~name:"session: forged too many fields"
      (forge_session ~salt:"" "H5H5H5H5H")
      ~salt:"";
    neg_session_decode ~name:"session: wrong salt" session_salt_tok
      ~salt:"wrong";
    neg_session_decode ~name:"session: only today rejects yesterday key"
      session_yesterday_tok ~salt:"";
    neg_session_validate ~name:"session: expired" session_10min_tok ~salt:""
      ~now:(fixed_now + 601) ~logout_at:0 ();
    neg_session_validate ~name:"session: expiry boundary at 600s"
      session_10min_tok ~salt:"" ~now:(fixed_now + 600) ~logout_at:0 ();
    neg_session_validate ~name:"session: future (beyond skew)"
      session_future_tok ~salt:"" ~now:fixed_now ~logout_at:0 ();
    neg_session_validate ~name:"session: future at 6s (just beyond skew)"
      session_future6_tok ~salt:"" ~now:fixed_now ~logout_at:0 ();
    neg_session_validate ~name:"session: logged out" session_tok ~salt:""
      ~now:fixed_now ~logout_at:fixed_now ();
    neg_session_validate ~name:"session: admin logged out" session_admin_tok
      ~salt:"" ~now:fixed_now ~logout_at:0 ~admin_logout_at:fixed_now ();
    neg_session_validate ~name:"session: missing admin_logout_at"
      session_admin_tok ~salt:"" ~now:fixed_now ~logout_at:0 ();
  ]
;;

let link_negatives () =
  [
    neg_link_decode ~name:"session token in link decoder" session_tok
      ~action:"login";
    neg_link_decode ~name:"CSRF token in link decoder" csrf_tok ~action:"login";
    neg_link_decode ~name:"link: tampered payload" (tamper link_tok 0)
      ~action:"login";
    neg_link_decode ~name:"link: tampered signature"
      (tamper link_tok (String.length link_tok - 1))
      ~action:"login";
    neg_link_decode ~name:"link: invalid char in signature"
      (corrupt_sig link_tok) ~action:"login";
    neg_link_decode ~name:"link: forged empty field"
      (forge_link ~action:"login" "H55H")
      ~action:"login";
    neg_link_decode ~name:"link: forged leading zero"
      (forge_link ~action:"login" "GH5H5H")
      ~action:"login";
    neg_link_decode ~name:"link: forged field too long"
      (forge_link ~action:"login" "H5H5HHGGGGGGGGGGGGGGG")
      ~action:"login";
    neg_link_decode ~name:"link: forged invalid char in payload"
      (forge_link ~action:"login" "A5H5H")
      ~action:"login";
    neg_link_decode ~name:"link: forged too few fields"
      (forge_link ~action:"login" "H5H")
      ~action:"login";
    neg_link_decode ~name:"link: forged too many fields"
      (forge_link ~action:"login" "H5H5H5H")
      ~action:"login";
    neg_link_decode ~name:"link: wrong action" link_tok ~action:"password-reset";
    neg_link_decode ~name:"link: only today rejects yesterday key"
      link_yesterday_tok ~action:"login";
    neg_link_validate ~name:"link: expired" link_10min_tok ~action:"login"
      ~now:(fixed_now + 601) ~last_nonce_at:0;
    neg_link_validate ~name:"link: expiry boundary at 600s" link_10min_tok
      ~action:"login" ~now:(fixed_now + 600) ~last_nonce_at:0;
    neg_link_validate ~name:"link: future (beyond skew)" link_future_tok
      ~action:"login" ~now:fixed_now ~last_nonce_at:0;
    neg_link_validate ~name:"link: future at 6s (just beyond skew)"
      link_future6_tok ~action:"login" ~now:fixed_now ~last_nonce_at:0;
    neg_link_validate ~name:"link: nonce consumed" link_tok ~action:"login"
      ~now:fixed_now ~last_nonce_at:fixed_now;
  ]
;;

let csrf_negatives () =
  [
    neg_csrf ~name:"session token in CSRF validator" session_tok
      ~form_id:"login" ~user_id:1;
    neg_csrf ~name:"link token in CSRF validator" link_tok ~form_id:"login"
      ~user_id:1;
    neg_csrf ~name:"CSRF: tampered payload" (tamper csrf_tok 0) ~form_id:"login"
      ~user_id:1;
    neg_csrf ~name:"CSRF: tampered signature"
      (tamper csrf_tok (String.length csrf_tok - 1))
      ~form_id:"login" ~user_id:1;
    neg_csrf ~name:"CSRF: invalid char in signature" (corrupt_sig csrf_tok)
      ~form_id:"login" ~user_id:1;
    neg_csrf ~name:"CSRF: wrong form_id" csrf_tok ~form_id:"settings" ~user_id:1;
    neg_csrf ~name:"CSRF: wrong user_id" csrf_tok ~form_id:"login" ~user_id:999;
    neg_csrf ~name:"CSRF: only today rejects yesterday key" csrf_yesterday_tok
      ~form_id:"login" ~user_id:1;
  ]
;;

(* ===== Main: assemble and output JSON ===== *)

let () =
  let json =
    `Assoc
      [
        "spec_version", `String "1.0rc5";
        "generated_by", `String "ocaml/bwt_vectors.ml";
        "bwt_epoch", `Int bwt_epoch;
        "fixed_now", `Int fixed_now;
        ( "keys",
          `Assoc
            [
              "today", `String (hex_of_string key_today);
              "yesterday", `String (hex_of_string key_yesterday);
            ] );
        ( "session",
          `Assoc
            [
              "positive", `List (session_positives ());
              "negative", `List (session_negatives ());
            ] );
        ( "link",
          `Assoc
            [
              "positive", `List (link_positives ());
              "negative", `List (link_negatives ());
            ] );
        ( "csrf",
          `Assoc
            [
              "positive", `List (csrf_positives ());
              "negative", `List (csrf_negatives ());
            ] );
      ]
  in
  Yojson.Basic.pretty_to_channel stdout json;
  print_newline ()
;;

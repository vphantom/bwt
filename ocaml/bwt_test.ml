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
  | exception Invalid_argument _ -> ()
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
    "empty" (Error "Bwt: bad safe-hex") (Bwt.safehex_to_int "")
;;

let test_int_of_safehex_invalid () =
  Alcotest.(check (result int string))
    "lowercase" (Error "Bwt: bad safe-hex") (Bwt.safehex_to_int "g");
  Alcotest.(check (result int string))
    "digit" (Error "Bwt: bad safe-hex") (Bwt.safehex_to_int "0");
  Alcotest.(check (result int string))
    "hex letter" (Error "Bwt: bad safe-hex") (Bwt.safehex_to_int "A");
  Alcotest.(check (result int string))
    "mixed valid/invalid" (Error "Bwt: bad safe-hex") (Bwt.safehex_to_int "GA");
  Alcotest.(check (result int string))
    "leading zero" (Error "Bwt: bad safe-hex") (Bwt.safehex_to_int "GG");
  Alcotest.(check (result int string))
    "17 chars overflow" (Error "Bwt: integer overflow")
    (Bwt.safehex_to_int "HHGGGGGGGGGGGGGGG");
  Alcotest.(check (result int string))
    "2^62 overflow" (Error "Bwt: integer overflow")
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

let () =
  Alcotest.run "BWT"
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
        ] );
    ]
;;

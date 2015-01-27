(* A simple JWT library for OCaml *)

type algorithm = 
	| None
	| HS256
	| HS384
	| HS512

type jwt_header = {
	alg: algorithm
}
type jwt_payload = {
	claims: (string * string) list
}

type t = {
	header: jwt_header;
	payload: jwt_payload;
	signature: string option;
}

module SignedToken = struct
	open Nocrypto
	open Nocrypto.Uncommon
	open Nocrypto.Hash

	let signing_func = function
		| None -> (fun ~key _ -> Cstruct.of_string "")
		| HS256 -> SHA256.hmac
		| HS384 -> SHA384.hmac
		| HS512 -> SHA512.hmac

	let signature data alg key = 
		(signing_func alg) ~key:key data

	let verify data input_sig alg key = match input_sig with
		| Some s -> s = (signature data alg key)
		| None -> false
end

let encode payload algorithm key = ()

let verify key token =
	SignedToken.verify
let decode token key = ()
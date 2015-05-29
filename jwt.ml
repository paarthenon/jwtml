(* A simple JWT library for OCaml *)

exception Jwt_format_error of string

type claim =
	| String of string
	| Date of int
	| Float of float
	| Integer of int
	| Boolean of bool

type claims = (string * claim) list

type algorithm = 
	| HS256
	| HS384
	| HS512

type jwt_header =
	{ alg: algorithm option }


type jwt_base = {
	header: string;
	payload: string;
	signature: string option;
}
type t =
  {	header: claims; (* At this point the header is effectively useless *)
	payload: claims;
	signature: string option; }


module StringExt = struct
	let dequote str =
		let len = String.length str in
		if str.[0] = '\"' && str.[len-1] = '\"' then
			String.sub str 1 (len - 2)
		else
			str
end

module SignedToken = struct
	open Nocrypto.Hash

	let signing_func = function
		| HS256 -> SHA256.hmac
		| HS384 -> SHA384.hmac
		| HS512 -> SHA512.hmac

	let signature data alg key = 
		(signing_func alg) ~key:key data

	let verify data input_sig alg key = match input_sig with
		| Some s -> s = (signature data alg key)
		| None -> false
end

module B64 = struct
	let fix_padding str = 
		let len = Bytes.length str in
		let (q,r) = len / 4, len mod 4 in
		if r = 0 then str else
			let b64_proper = Bytes.make (4 * (q + 1)) '=' in
			Bytes.blit str 0 b64_proper 0 len;
			b64_proper

	let decode str =
		str
		|> fix_padding
		|> Cstruct.of_string
		|> Nocrypto.Base64.decode
		|> Cstruct.to_string

	let encode str =
		str
		|> Cstruct.of_string
		|> Nocrypto.Base64.encode
		|> Cstruct.to_string
end

let alg_of_str = function
	| "HS256" -> Some HS256
	| "HS384" -> Some HS384
	| "HS512" -> Some HS512
	| "None" -> None
	| _ -> raise (Jwt_format_error "Unsupported algorithm")

let str_of_alg = function
	| Some HS256 -> "HS256"
	| Some HS384 -> "HS384"
	| Some HS512 -> "HS512"
	| None -> "none"

let parse alg token =
	token
	|> Str.split (Str.regexp "\\.")
	|> List.map B64.decode
	|> function
		| header::payload::t ->
			let open Yojson.Basic in

			let claims_of_json json = match (from_string json) with 
				| `Assoc list -> list
					|> List.map (fun (a,b) -> (a, StringExt.dequote(to_string b)))
					|> List.map (fun (a,b) -> (a, String b))
				| _ -> raise (Jwt_format_error "Invalid Token")
			in

			let header_claims = claims_of_json header in
			let payload_claims = claims_of_json payload in

			let signature = match t with
				| [] -> if alg = None then None else raise (Jwt_format_error "No signature present despite an algorithm being specified")
				| [x] -> Some x
				| _ -> raise @@ Jwt_format_error "Invalid Jwt structure. More than 3 parts"
			in
			{
				header = header_claims;
				payload = payload_claims;
				signature = signature
			}
		| _ -> raise (Jwt_format_error "Improper input. Expected a period-delimited string with two or three parts")

let json_of_claims claims = 
	let to_json = function
		| String s -> `String s
		| Float n -> `Float n
		| Integer i -> `Int i
		| Date d -> `Int d
		| Boolean b -> `Bool b
	in
	let rec convert_claims = function
		| ((t, c)::tl) -> (t, to_json c)::convert_claims(tl)
		| [] -> []
	in
	`Assoc (convert_claims claims)

let encode token =
	let headj = json_of_claims token.header in
	let claimsj = json_of_claims token.payload in
	let compile x = B64.encode (Yojson.Basic.to_string x) in
	String.concat "." [compile headj ; compile claimsj ; "signature"]

let validate alg key token =
	(*
		- Verify token structure (accomplished through parsing)
		- Verify signature is accurate
		- 
	*)
	let rec split_last sofar = function
		| h::t -> split_last (h::sofar) t
		| [x] -> (List.rev sofar, Some x)
		| [] -> ([], None)
	in
	let (front, back) = split_last [] [] in
	ignore(front,back);true

let decode token key = 
	if validate HS256 "" token then Some (parse None token) else None
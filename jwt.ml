(* A simple JWT library for OCaml *)

exception Jwt_format_error of string

type algorithm = 
	| HS256
	| HS384
	| HS512

type jwt_header =
	{ alg: algorithm option }

type jwt_payload = 
	{ claims: (string * string) list }

type t =
  {	header: jwt_header;
	payload: jwt_payload;
	signature: string option; }

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
	| None -> "None"

let dequote str =
	let len = String.length str in
	if str.[0] = '\"' && str.[len-1] = '\"' then
		String.sub str 1 (len - 2)
	else
		str

let enquote str = String.concat "" ["\"";str;"\""]

let parse token =
	token
	|> Str.split (Str.regexp "\\.")
	|> List.map B64.decode
	|> function
		| head::payload::t ->
			let open Yojson.Basic in

			let alg = head |> from_string |> Util.member "alg" |> to_string |> dequote |> alg_of_str in
			let claims = match (from_string payload) with 
				| `Assoc list -> List.map (fun (a,b) -> (a,to_string b)) list
				| _ -> raise (Jwt_format_error "Invalid payload")
			in
			let signature = match t with
				| [] -> if alg = None then None else raise (Jwt_format_error "No signature present despite an algorithm being specified")
				| [x] -> Some x
				| _ -> raise @@ Jwt_format_error "Invalid Jwt structure. More than 3 parts"
			in
			{
				header = {
					alg = alg	
				};
				payload = {
					claims = claims
				};
				signature = signature
			}
		| _ -> raise (Jwt_format_error "Improper input. Expected a period-delimited string with two or three parts")

let json_of_header h =
	let alg_str = (str_of_alg(h.alg)) in
	`Assoc
	[
		("type", `String "JWT");
		("alg", `String alg_str)

	]

let json_of_claims claims = 
	let rec convert_claims = function
		| ((t,c)::tl) -> (t,`String  c)::convert_claims(tl)
		| [] -> []
	in
	`Assoc (convert_claims claims)

let encode token =
	let headj = json_of_header token.header in
	let claimsj = json_of_claims token.payload.claims in
	let compile x = B64.encode (Yojson.Basic.to_string x) in
	String.concat "." [compile headj ; compile claimsj ; "signature"]

let verify key token =
	SignedToken.verify
let decode token key = ()
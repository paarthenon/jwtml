(* 
	A simple JWT library for OCaml

	Does NOT support nested tokens.
*)

exception Jwt_format_error of string

type algorithm = 
	| HS256
	| HS384
	| HS512

type jwt_base = {
	header: string;
	payload: string;
	signature: string option;
}
type t =
  {	header: (string * Yojson.Basic.json) list;
	payload: (string * Yojson.Basic.json) list;
	signature: string option; }


(*
	The algorithm translation functions are not as useful as they first seem.
	There is a security issue with JWTs in that you need to validate the token
	but in order to validate the token you must first already trust the token
	to give you an accurate algorithm field.

	In real applications programmers will generally know what hash algorithm
	is being used and so our parse functionality will require an algorithm be
	specified.
*)
module Guts = struct (* Usually referred to as 'Internals' *)
	let (>>=) opt f = match opt with Some x -> Some (f x) | None -> None

	let alg_of_str = function
		| "HS256" -> Some HS256
		| "HS384" -> Some HS384
		| "HS512" -> Some HS512
		| "none" -> None
		| _ -> raise (Jwt_format_error "Unsupported algorithm")

	let str_of_alg = function
		| Some HS256 -> "HS256"
		| Some HS384 -> "HS384"
		| Some HS512 -> "HS512"
		| None -> "none"

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
end

open Guts

(* JWT Reserved Claims *)
let alg jwt = List.assoc "alg" jwt.header |> function `String s -> Some (alg_of_str s) | _ -> None

let iss jwt = List.assoc "iss" jwt.payload |> function `String s -> Some s | _ -> None
let sub jwt = List.assoc "sub" jwt.payload |> function `String s -> Some s | _ -> None
let aud jwt = List.assoc "aud" jwt.payload |> function `String s -> Some s | _ -> None

(* Apparently OCaml does not have a built-in date type. That's... bad. *)
let exp jwt = List.assoc "exp" jwt.payload |> function `Int d -> Some d | _ -> None
let exp jwt = List.assoc "nbf" jwt.payload |> function `Int d -> Some d | _ -> None
let iat jwt = List.assoc "iat" jwt.payload |> function `Int d -> Some d | _ -> None

let jti jwt = List.assoc "aud" jwt.payload |> function `Int i -> Some i | _ -> None

let parse token =
	token
	|> Str.split (Str.regexp "\\.")
	|> List.map B64.decode
	|> function
		| header::payload::t ->
			let get_dict = function `Assoc d -> d | _ -> raise (Jwt_format_error "Improperly formatted header or payload") in
			let header' = header |> Yojson.Basic.from_string |> get_dict in
			let payload' = payload |> Yojson.Basic.from_string |> get_dict in

			let alg = List.assoc "alg" header'
				|> (function `String s -> s | _ -> raise (Jwt_format_error "Algorithm is not a string"))
				|> alg_of_str
			in
			let signature = match t with
				| [] -> if alg = None then None else raise (Jwt_format_error "No signature present despite an algorithm being specified")
				| [x] -> Some x
				| _ -> raise @@ Jwt_format_error "Invalid Jwt structure. More than 3 parts"
			in
			{
				header = header';
				payload = payload';
				signature = signature
			}
		| _ -> raise (Jwt_format_error "Improper input. Expected a period-delimited string with two or three parts")



let encode token =
	let compile x = `Assoc x |> Yojson.Basic.to_string |> B64.encode in
	match token.signature with
		| Some s -> String.concat "." [compile token.header; compile token.payload; s]
		| None -> String.concat "." [compile token.header; compile token.payload]

let validate alg key token =
	(*
		- Verify token structure (accomplished through parsing)
		- Verify signature is accurate
		- 
	*)
	let split_last l = 
		let rec helper sofar = function
			| [] -> ([], None)
			| [x] -> (List.rev sofar, Some x)
			| h::t -> helper (h::sofar) t
		in
		helper [] l
	in
	let (front, final) = Str.split (Str.regexp "\\.") token |> split_last in
	let payload, signature =
		(Cstruct.of_string (String.concat "." front)),
		final
			>>= B64.decode
			>>= Cstruct.of_string
	in
	SignedToken.verify payload signature alg (Cstruct.of_string key)

let decode alg key token = 
	(*
		- verify signed token
		- parse token
		- Otherwise list of errors (or exceptions, though that would suck). 
	*)
	if validate HS256 key token then Some (parse token) else None

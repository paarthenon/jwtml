(* 
	A simple JWT library for OCaml

	Does NOT support nested tokens.
*)

exception Jwt_format_error of string
exception Jwt_error of string

type algorithm = 
	| HS256
	| HS384
	| HS512

type key = algorithm * string

type t =
  {	header: (string * Yojson.Basic.json) list;
	payload: (string * Yojson.Basic.json) list;
	signature: string option; }

module Guts = struct (* Usually referred to as 'Internals' *)
	let (>>=) opt f = match opt with Some x -> Some (f x) | None -> None
	(*
		The algorithm translation functions are not as useful as they first seem.
		There is a security issue with JWTs in that you need to validate the token
		but in order to validate the token you must first already trust the token
		to give you an accurate algorithm field.

		In real applications programmers will generally know what hash algorithm
		is being used and so our parse functionality will require an algorithm be
		specified.
	*)
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

		let sign alg key data = 
			(signing_func alg) ~key:(Cstruct.of_string key) (Cstruct.of_string data)
			|> Cstruct.to_string

		let verify data input_sig alg key = match input_sig with
			| Some s -> s = (sign alg key data)
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
let alg jwt = List.assoc "alg" jwt.header |> function `String s -> alg_of_str s | _ -> None

let iss jwt = List.assoc "iss" jwt.payload |> function `String s -> Some s | _ -> None
let sub jwt = List.assoc "sub" jwt.payload |> function `String s -> Some s | _ -> None
let aud jwt = List.assoc "aud" jwt.payload |> function `String s -> Some s | _ -> None

(* Apparently OCaml does not have a built-in date type. That's... bad. *)
let exp jwt = List.assoc "exp" jwt.payload |> function `Int d -> Some d | _ -> None
let nbf jwt = List.assoc "nbf" jwt.payload |> function `Int d -> Some d | _ -> None
let iat jwt = List.assoc "iat" jwt.payload |> function `Int d -> Some d | _ -> None

let jti jwt = List.assoc "aud" jwt.payload |> function `Int i -> Some i | _ -> None

let parse token =
	token
	|> Str.split (Str.regexp "\\.")
	|> List.map B64.decode
	|> function
		| header::payload::t ->
			(* extract dicts *)
			let [header'; payload'] = 
				[header; payload]
				|> List.map Yojson.Basic.from_string
				|> List.map (function
					| `Assoc d -> d
					| _ -> raise (Jwt_format_error "Improperly formatted header or payload"))
			in
			(* This may be more fitting in token validation *)
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

let encode (algorithm, key) token =
	let compile x = `Assoc x |> Yojson.Basic.to_string |> B64.encode in

	let signed_token = match (alg token) with
		| Some alg' when alg' = algorithm -> 
			let signature = [token.header; token.payload]
				|> List.map compile
				|> String.concat "." 
				|> SignedToken.sign alg' key 
			in
			{ token with signature = Some signature }
		| Some alg' -> 
			let err_str = (Printf.sprintf "Algorithm mismatch! Jwt has algorithm %s. %s was expected." 
				(str_of_alg (Some alg')) (str_of_alg (Some algorithm))) in
			raise (Jwt_error err_str)
		| None -> token
	in
	(* I feel like there's a more elegant way to do this *)
	match signed_token.signature with
		| Some s -> String.concat "." [compile signed_token.header; compile signed_token.payload; B64.encode s]
		| None -> String.concat "." [compile signed_token.header; compile signed_token.payload]

let validate_signature alg key token =
	let split_last l = 
		let rec helper sofar = function
			| [] -> ([], None)
			| [x] -> (List.rev sofar, Some x)
			| h::t -> helper (h::sofar) t
		in
		helper [] l
	in
	let (front, final) = Str.split (Str.regexp "\\.") token |> split_last in
	let payload = (String.concat "." front) in
	let signature = final
		>>= B64.decode
	in
	SignedToken.verify payload signature alg key

module Validation = struct
	let test_exp time token = match (exp token) with Some s -> (float_of_int s) > time | None -> false
	let test_nbf time token = match (nbf token) with Some s -> (float_of_int s) < time | None -> false
	let none _ = true
	let date token =
		[test_exp; test_nbf] 
		|> List.fold_left (fun a f -> a && f (Unix.time ()) token) true
	let trust _ = true
	let unique _ = true
end

let decode (alg,key) ?(validate = Validation.date) token = 
	(*
		- verify signed token
		- parse token
		- Otherwise list of errors (or exceptions, though that would suck). 
	*)
	let token' = if validate_signature HS256 key token then Some (parse token) else None in
	match token' with
		| Some t -> if validate t then token' else None
		| None -> None

let claim str jwt = List.assoc str jwt.payload

let add_claim str json jwt = 
	{ jwt with payload = (str, json)::jwt.payload }
(* 
	A simple JWT library for OCaml

	Does NOT support nested tokens.
*)
exception Jwt_format_error of string
exception Jwt_error of string

type json = Yojson.Basic.json

type t =
  {	header: (string * json) list;
	payload: (string * json) list;
	signature: string option }


module Guts = struct
	open Signing
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
		| _ -> None

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

let encode ?key token =
	let compile x = `Assoc x |> Yojson.Basic.to_string |> B64.encode in
	let b64_jwt = 
		[token.header; token.payload]
		|> List.map compile
		|> String.concat "."
	in
	match key with
		| Some (alg, secret) ->
			String.concat "." [b64_jwt; (Signing.sign (alg,secret) b64_jwt)]
		| None -> b64_jwt

	(*TODO: check alg in Signing.key vs. alg_token*)

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
	final
		>>= B64.decode
		|> (function
			| Some s -> Signing.verify (alg, key) s payload
			| None -> false)

let decode ?key ?validate token = 
	(*
		- verify signed token
		- parse token
		- Otherwise list of errors (or exceptions, though that would suck). 
	*)
	let valid_cert = match key with
		| Some (alg, secret) -> validate_signature alg secret token
		| None -> true
	in

	if valid_cert then
		let parsed = parse token in
		match validate with
			| Some validate -> (if validate parsed then Some parsed else None)
			| None -> Some parsed
	else None

let claim str jwt = List.assoc str jwt.payload
let claims jwt = jwt.payload
let add_claim str json jwt = 
	{ jwt with payload = (str, json)::jwt.payload }
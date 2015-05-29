(* A simple JWT library for OCaml *)

exception Jwt_format_error of string


type value =
	| String of string
	| Date of int
	| Float of float
	| Integer of int
	| Boolean of bool
	| List of value list
	| Dict of (string * value) list

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
  {	header: (string * value) list; (* At this point the header is effectively useless, so I don't want to elevate metadata *)
	payload: (string * value) list;
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

let alg jwt = List.assoc "alg" jwt.header |> function String s -> Some (alg_of_str s) | _ -> None

let iss jwt = List.assoc "iss" jwt.payload |> function String s -> Some s | _ -> None
let sub jwt = List.assoc "sub" jwt.payload |> function String s -> Some s | _ -> None
let aud jwt = List.assoc "aud" jwt.payload |> function String s -> Some s | _ -> None

(* Apparently OCaml does not have a built-in date type. That's... bad. *)
let exp jwt = List.assoc "exp" jwt.payload |> function Date d -> Some d | _ -> None
let exp jwt = List.assoc "exp" jwt.payload |> function Date d -> Some d | _ -> None
let iat jwt = List.assoc "iat" jwt.payload |> function Date d -> Some d | _ -> None


let jti jwt = List.assoc "aud" jwt.payload |> function Integer i -> Some i | _ -> None

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

module Json = struct
	let rec from_value = function
		| String s -> `String s
		| Float n -> `Float n
		| Integer i -> `Int i
		| Date d -> `Int d
		| Boolean b -> `Bool b
		| List l -> `List (List.map from_value l)
		| Dict kvp -> `Assoc ( List.map (fun (k,v) -> (k, from_value v)) kvp )

	let rec to_value = function
		| `String s -> String s
		| `Float f -> Float f
		| `Int i -> Integer i
		| `Date d -> Date d
		| `Bool b -> Boolean b
		| `List l -> List (List.map to_value l)
		| `Assoc kvp -> Dict ( List.map (fun (k,v) -> (k, to_value v)) kvp )
		| `Null -> raise (Jwt_format_error "Cannot currently support null")

	let from_string s = to_value (Yojson.Basic.from_string s)
	let to_string v = Yojson.Basic.to_string (from_value v)
end


let parse alg token =
	token
	|> Str.split (Str.regexp "\\.")
	|> List.map B64.decode
	|> function
		| header::payload::t ->
			let get_dict = function Dict d -> d | _ -> raise (Jwt_format_error "Improperly formatted header or payload") in
			let header' = header |> Json.from_string  |> get_dict in
			let payload' = payload |> Json.from_string |> get_dict in

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
	let headj = Json.from_value (Dict token.header) in
	let claimsj = Json.from_value (Dict token.payload) in
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
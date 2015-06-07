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
	signature: string option }


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

let decode (alg,key) ?validate token = 
	(*
		- verify signed token
		- parse token
		- Otherwise list of errors (or exceptions, though that would suck). 
	*)
	if validate_signature alg key token then
		let tok = parse token in
		match validate with
			| Some validate -> 
				if validate tok then Some tok else None
			| None -> Some tok
	else None

let claim str jwt = List.assoc str jwt.payload
let claims jwt = jwt.payload
let add_claim str json jwt = 
	{ jwt with payload = (str, json)::jwt.payload }
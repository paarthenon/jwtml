open Jwt


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
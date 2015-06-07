type algorithm = 
	| HS256
	| HS384
	| HS512

type t

type key = algorithm * string

val encode : key -> t -> string

val decode : key -> ?validate:(t -> bool) -> string -> t option

(* claim manipulation *)
val claim : string -> t -> Yojson.Basic.json

val add_claim : string -> Yojson.Basic.json -> t -> t

(* Meta info *)
val alg : t -> algorithm option
(* I actually kind of hate this because 
NO alg specified, invalid alg specified,
and unsupported alg specified are three
different things *)

(* registered claims *)
val iss : t -> string option
val sub : t -> string option
val aud : t -> string option

val exp : t -> int option
val nbf : t -> int option
val iat : t -> int option
val jti : t -> int option

module Guts : sig
	module B64 : sig
		val encode : string -> string
		val decode : string -> string
	end
end

module Validation : sig
	(* val _ : t -> bool (* future type *)*)
	val none : t -> bool
	val date : t -> bool (* float -> t -> bool *)
	val trust : t -> bool (* trust_info -> t -> bool *)
	val unique : t -> bool (* jwt_registry -> t -> bool *)
end
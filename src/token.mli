open Signing

type t 

val encode : key -> t -> string (*TODO: change key to key option*)
val decode : ?key:Signing.key -> ?validate:(t -> bool) -> string -> t option

(* claim manipulation *)
val claim : string -> t -> Yojson.Basic.json
val claims : t -> (string * Yojson.Basic.json) list
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

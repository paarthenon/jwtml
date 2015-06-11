open Signing

type t 

type json = [
  | `Assoc of (string * json) list
  | `Bool of bool
  | `Float of float
  | `Int of int
  | `List of json list
  | `Null
  | `String of string
]

val encode : ?key:Signing.key -> t -> string (*TODO: change key to key option*)
val decode : ?key:Signing.key -> ?validate:(t -> bool) -> string -> t option

(* claim manipulation *)
val claim : string -> t -> json
val claims : t -> (string * json) list
val add_claim : string -> json -> t -> t

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

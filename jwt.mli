type algorithm = 
	| HS256
	| HS384
	| HS512

type t

type key = algorithm * string

(* parse does not actually do any validation. Is this worthwhile to publish?*)
val parse : string -> t (*TODO: T result*)

val encode : key -> t -> string

val decode : key -> string -> t option

val claim : string -> t -> Yojson.Basic.json

val add_claim : string -> Yojson.Basic.json -> t -> t
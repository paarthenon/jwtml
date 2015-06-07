type algorithm =
	| HS256
	| HS384
	| HS512

type key = algorithm * string

val sign : key -> string -> string
val verify : key -> string -> string -> bool
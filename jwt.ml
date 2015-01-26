(* A simple JWT library for OCaml *)

module JWT = struct
	type algorithm = 
		| HS256

	let encode payload algorithm key = ()

	let decode payload algorithm key = ()
end

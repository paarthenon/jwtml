open Nocrypto.Hash

let signing_func = function
	| HS256 -> SHA256.hmac
	| HS384 -> SHA384.hmac
	| HS512 -> SHA512.hmac

let sign (alg,key) data = 
	(signing_func alg) ~key:(Cstruct.of_string key) (Cstruct.of_string data)
	|> Cstruct.to_string

let verify cert_key input_sig alg key = match input_sig with
	| Some s -> s = (sign cert_key data)
	| None -> false
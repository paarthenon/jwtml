open Nocrypto.Hash

type algorithm =
	| HS256
	| HS384
	| HS512

type key = algorithm * string

let signing_func = function
	| HS256 -> SHA256.hmac
	| HS384 -> SHA384.hmac
	| HS512 -> SHA512.hmac

let sign (alg,key) data = 
	(signing_func alg) ~key:(Cstruct.of_string key) (Cstruct.of_string data)
	|> Cstruct.to_string

let verify cert_key input_sig data = input_sig = sign cert_key data
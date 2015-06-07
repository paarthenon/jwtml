open Nocrypto

let fix_padding str = 
	let len = Bytes.length str in
	let (q,r) = len / 4, len mod 4 in
	if r = 0 then str else
		let b64_proper = Bytes.make (4 * (q + 1)) '=' in
		Bytes.blit str 0 b64_proper 0 len;
		b64_proper

let decode str =
	str
	|> fix_padding
	|> Cstruct.of_string
	|> Nocrypto.Base64.decode
	|> Cstruct.to_string

let encode str =
	str
	|> Cstruct.of_string
	|> Nocrypto.Base64.encode
	|> Cstruct.to_string
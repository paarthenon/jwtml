open Token

let test_exp time token = match (exp token) with Some s -> (float_of_int s) > time | None -> false
let test_nbf time token = match (nbf token) with Some s -> (float_of_int s) < time | None -> false

let none _ = true
let date token =
	test_exp (Unix.time ()) token && test_nbf (Unix.time ()) token
let trust _ = true
let unique _ = true

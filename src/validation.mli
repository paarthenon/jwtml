open Token
(* val _ : t -> bool (* future type *)*)
val none : t -> bool
val date : t -> bool (* float -> t -> bool *)
val trust : t -> bool (* trust_info -> t -> bool *)
val unique : t -> bool (* jwt_registry -> t -> bool *)

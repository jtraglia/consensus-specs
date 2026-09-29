namespace Spec

abbrev Uint8 := Nat
abbrev Uint16 := Nat
abbrev Uint32 := Nat
abbrev Uint64 := Nat
abbrev Uint256 := Nat

abbrev Result (value : Type) := Except String value

def assert (condition : Bool) : Result Unit :=
  if condition then .ok () else .error "assertion failed"

end Spec

import Ssz

/-!
What the specification is written against.

Every type the specification declares becomes an ordinary Lean structure, so a
field is read as `state.slot` and a copy with fields changed is written
`{ state with slot := s }`. Sequences become `Sequence`, whose operations are
named after the Python ones they stand for.

A definition that can reject returns `Result`. Indexing and assigning past the
end of a sequence reject, which is what an `IndexError` does in Python, and
`assert` rejects the way Python's `assert` does. Nothing here panics, so no
definition can take the process down with it.
-/

namespace Spec

open Ssz

/-- Lean has `BEq` and `DecidableEq` for bytes, but no way to print them. -/
instance : Repr ByteArray where
  reprPrec data precedence := reprPrec data.data precedence

/-- A definition either produces a value, or rejects what it was given. -/
abbrev Result := Except String

/-- Reject, naming the reason. -/
def reject {a : Type} (reason : String) : Result a := .error reason

/-- Reject unless a condition holds, the way Python's `assert` does. -/
def assert (condition : Bool) (reason : String := "assertion failed") : Result Unit :=
  if condition then .ok () else .error reason

/-!
Sequences.

`List[T, N]`, `Vector[T, N]` and `ProgressiveList[T]` all become a `Sequence`,
which differs from a Lean `Array` in one way: reading or writing past the end
rejects rather than needing a proof or panicking.
-/

/-- What the specification declares as a `List`, a `Vector` or a `ProgressiveList`. -/
structure Sequence (a : Type) where
  elements : Array a
deriving Repr, BEq, Inhabited

namespace Sequence

variable {a : Type}

/-- `len(xs)`. -/
def size (xs : Sequence a) : Nat := xs.elements.size

/-- `xs[index]`, which rejects when the index is past the end. -/
instance : GetElem (Sequence a) Nat (Result a) (fun _ _ => True) where
  getElem xs index _ :=
    if valid : index < xs.elements.size then .ok xs.elements[index]
    else .error s!"index {index} out of range"

/-- `xs[index] = value`, which rejects when the index is past the end. -/
def set (xs : Sequence a) (index : Nat) (value : a) : Result (Sequence a) :=
  if index < xs.size then .ok (Sequence.mk (xs.elements.setIfInBounds index value))
  else .error s!"index {index} out of range"

/-- `xs.append(value)`. -/
def append (xs : Sequence a) (value : a) : Sequence a :=
  Sequence.mk (xs.elements.push value)

end Sequence

/-!
The pieces the generated conversions to and from `Ssz.Value` are built out of.
A specification does not name these.
-/

/-- The nth field of a struct, or the nth element of a sequence. -/
def field (value : Value) (index : Nat) : Value :=
  match value with
  | .seq elements => elements.getD index (.bool false)
  | _ => .bool false

/-- The default value of a type, which is what `empty()` gives in Python. -/
def defaultOf (shape : Desc) : Value :=
  match Desc.default shape with
  | .ok value => value
  | .error _ => .seq []

/-! Readers for each shape a value can take. A value that has been checked
against its type cannot take the wrong shape, so these do not fail. -/

def asNat : Value -> Nat
  | .uint n => n
  | _ => 0

def asBool : Value -> Bool
  | .bool b => b
  | _ => false

def asBytes : Value -> ByteArray
  | .bytes data => ByteArray.mk data
  | _ => ByteArray.mk #[]

def asBits : Value -> Array Bool
  | .bits data => data
  | _ => #[]

def asElements : Value -> Array Value
  | .seq elements => elements.toArray
  | _ => #[]

/-! Writers, for the conversion back. -/

def ofNat (n : Nat) : Value := .uint n
def ofBool (b : Bool) : Value := .bool b
def ofBytes (data : ByteArray) : Value := .bytes data.data
def ofBits (data : Array Bool) : Value := .bits data
def ofElements (elements : Array Value) : Value := .seq elements.toList

/-!
The wire format.

Arguments arrive as a run of frames, each a four-byte little-endian length
followed by that many bytes of SSZ. The reply is a status byte -- zero for a
result, one for a rejection -- followed by the encoded result or the reason as
UTF-8.
-/

/-- Read a four-byte little-endian length. -/
private def readLength (data : ByteArray) (start : Nat) : Nat :=
  (data.get! start).toNat
    ||| ((data.get! (start + 1)).toNat <<< 8)
    ||| ((data.get! (start + 2)).toNat <<< 16)
    ||| ((data.get! (start + 3)).toNat <<< 24)

/-- Split a framed argument blob into one byte string per argument. -/
partial def unframe (data : ByteArray) : Array ByteArray :=
  let rec go (offset : Nat) (acc : Array ByteArray) : Array ByteArray :=
    if offset + 4 > data.size then acc
    else
      let length := readLength data offset
      let start := offset + 4
      if start + length > data.size then acc
      else go (start + length) (acc.push (data.extract start (start + length)))
  go 0 #[]

/-- Decode one argument against the type it is declared to have. -/
def decodeArg (shape : Desc) (data : ByteArray) : Result Value :=
  match Ssz.deserialize shape data.data with
  | .ok value => .ok value
  | .error e => .error s!"argument did not decode: {repr e}"

/-- Encode a result against the type it is declared to have. -/
def encodeResult (shape : Desc) (value : Value) : Result ByteArray :=
  match Ssz.serialize shape value with
  | .ok bytes => .ok (ByteArray.mk bytes)
  | .error e => .error s!"result did not encode: {repr e}"

/-- Prefix a successful reply with its status byte. -/
def ok (payload : ByteArray) : ByteArray :=
  (ByteArray.mk #[0]) ++ payload

/-- Report a rejection as a reply. -/
def failure (reason : String) : ByteArray :=
  (ByteArray.mk #[1]) ++ reason.toUTF8

/-- Turn a result into the reply the caller reads. -/
def reply (result : Result ByteArray) : ByteArray :=
  match result with
  | .ok payload => ok payload
  | .error reason => failure reason

end Spec

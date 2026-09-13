import Spec.Notation
import Ssz

/-!
What the generated specification is written against.

Each SSZ type becomes an ordinary Lean structure, so a field is read as
`state.slot`, a copy with one field changed is `{ state with slot := x }`, and a
`do` block that declares `let mut state` can assign to `state.slot` directly.

The helpers here are what the generated conversions to and from `Ssz.Value` are
built out of. Writing a specification needs `assert` and little else.
-/

namespace Spec

open Ssz

/-- Lean has `BEq` and `DecidableEq` for bytes, but no way to print them. -/
instance : Repr ByteArray where
  reprPrec data precedence := reprPrec data.data precedence

/-- A definition either produces a value, or rejects what it was given. -/
abbrev Result := Except String

/-- Reject, naming the reason. -/
def reject {α : Type} (reason : String) : Result α := .error reason

/-- Reject unless a condition holds. -/
def check (condition : Bool) (reason : String) : Result Unit :=
  if condition then .ok () else .error reason

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

def asNat : Value → Nat
  | .uint n => n
  | _ => 0

def asUInt8 (value : Value) : UInt8 := UInt8.ofNat (asNat value)
def asUInt16 (value : Value) : UInt16 := UInt16.ofNat (asNat value)
def asUInt32 (value : Value) : UInt32 := UInt32.ofNat (asNat value)
def asUInt64 (value : Value) : UInt64 := UInt64.ofNat (asNat value)

def asBool : Value → Bool
  | .bool b => b
  | _ => false

def asBytes : Value → ByteArray
  | .bytes data => ⟨data⟩
  | _ => ⟨#[]⟩

def asBits : Value → Array Bool
  | .bits data => data
  | _ => #[]

def asSeq : Value → Array Value
  | .seq elements => elements.toArray
  | _ => #[]

/-! Writers, for the conversion back. -/

def ofNat (n : Nat) : Value := .uint n
def ofBool (b : Bool) : Value := .bool b
def ofBytes (data : ByteArray) : Value := .bytes data.data
def ofBits (data : Array Bool) : Value := .bits data
def ofSeq (elements : Array Value) : Value := .seq elements.toList

/-!
The wire format.

Arguments arrive as a run of frames, each a four-byte little-endian length
followed by that many bytes of SSZ. The reply is a status byte -- zero for a
result, one for a failed assertion -- followed by the encoded result or the
reason as UTF-8.
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
  | .ok bytes => .ok ⟨bytes⟩
  | .error e => .error s!"result did not encode: {repr e}"

/-- Prefix a successful reply with its status byte. -/
def ok (payload : ByteArray) : ByteArray :=
  (ByteArray.mk #[0]) ++ payload

/-- Report a failed assertion, or any refusal, as a reply. -/
def failure (reason : String) : ByteArray :=
  (ByteArray.mk #[1]) ++ reason.toUTF8

/-- Turn a result into the reply the caller reads. -/
def reply (result : Result ByteArray) : ByteArray :=
  match result with
  | .ok payload => ok payload
  | .error reason => failure reason

end Spec

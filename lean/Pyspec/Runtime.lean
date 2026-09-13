import Ssz

/-!
What the generated specification code is written against.

A spec value is an `Ssz.Value` under a one-field wrapper that names its type, so
that a `BeaconState` and an `Attestation` are different Lean types while both
stay in the shape the SSZ library reads. A wrapper of one field is erased by the
compiler, so naming a type this way costs nothing at runtime.
-/

namespace Pyspec

open Ssz

/-- A spec function either produces a value or fails the way `assert` does. -/
abbrev SpecM := Except String

/-- Fail the way a spec `assert` does. -/
def check (condition : Bool) (reason : String) : SpecM Unit :=
  if condition then .ok () else .error reason

/-- The nth field of a struct, or the nth element of a sequence. -/
def field (value : Value) (index : Nat) : Value :=
  match value with
  | .seq elements => elements.getD index (.bool false)
  | _ => .bool false

/-- The same value with its nth field replaced. -/
def setField (value : Value) (index : Nat) (replacement : Value) : Value :=
  match value with
  | .seq elements => .seq (elements.set index replacement)
  | _ => value

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

/-! Writers, for the setters the generated accessors provide. -/

def ofBytes (data : ByteArray) : Value := .bytes data.data
def ofBits (data : Array Bool) : Value := .bits data
def ofSeq (elements : Array Value) : Value := .seq elements.toList

/-- The default value of a type, as `empty()` gives in Python. -/
def defaultOf (shape : Desc) : Value :=
  match Desc.default shape with
  | .ok value => value
  | .error _ => .seq []

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
def decodeArg (shape : Desc) (data : ByteArray) : SpecM Value :=
  match Ssz.deserialize shape data.data with
  | .ok value => .ok value
  | .error e => .error s!"argument did not decode: {repr e}"

/-- Encode a result against the type it is declared to have. -/
def encodeResult (shape : Desc) (value : Value) : SpecM ByteArray :=
  match Ssz.serialize shape value with
  | .ok bytes => .ok ⟨bytes⟩
  | .error e => .error s!"result did not encode: {repr e}"

/-- Prefix a successful reply with its status byte. -/
def ok (payload : ByteArray) : ByteArray :=
  (ByteArray.mk #[0]) ++ payload

/-- Report a failed assertion, or any refusal, as a reply. -/
def failure (reason : String) : ByteArray :=
  (ByteArray.mk #[1]) ++ reason.toUTF8

/-- Turn a spec result into the reply the caller reads. -/
def reply (result : SpecM ByteArray) : ByteArray :=
  match result with
  | .ok payload => ok payload
  | .error reason => failure reason

end Pyspec

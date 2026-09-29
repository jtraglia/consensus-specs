def decode (width : Nat) (bytes : ByteArray) (offset : Nat) : Nat :=
  (List.range width).foldr (fun index total => total * 256 + (bytes.get! (offset + index)).toNat) 0

def encode (width : Nat) (value : Nat) : ByteArray :=
  ByteArray.mk ((Array.range width).map (fun index => ((value >>> (8 * index)) % 256).toUInt8))

def reply (status : UInt8) (payload : ByteArray) : ByteArray :=
  ByteArray.mk #[status] ++ payload

def finish (width : Nat) (value : Nat) : ByteArray :=
  if value < 2 ^ (8 * width) then reply 0 (encode width value)
  else reply 1 "result out of range".toUTF8

def finishResult (width : Nat) (value : Except String Nat) : ByteArray :=
  match value with
  | .ok result => finish width result
  | .error message => reply 1 message.toUTF8

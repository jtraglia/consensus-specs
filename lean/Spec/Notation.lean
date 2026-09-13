import Lean

/-!
The notation a specification is written in.

Lean has no assignment and no exceptions, which would otherwise show up on every
line of a specification that edits a state or rejects its input. Two pieces of
notation put those back:

- `assert c` rejects unless `c` holds, naming the condition the way Python's
  `assert` does.
- `x.f := v`, `x.f.g := v` and `x.f[i] := v` assign to a field of a `let mut`
  binding, and expand to the record update that Lean does have.

Neither is a new capability. They are the same terms, spelled the way the
specification reads.
-/

open Lean

namespace Spec

/-- Rebuild a term with the field path under it replaced, innermost first. -/
private partial def rebuild (target : Term) (path : List String) (value : Term) : MacroM Term :=
  match path with
  | [] => pure value
  | name :: rest => do
      let field := mkIdent (.mkSimple name)
      let inner ← rebuild (← `($target.$field:ident)) rest value
      `({ $target with $field:ident := $inner })

/-- Split a dotted name into the identifier it starts at and the fields under it. -/
private def split (name : Name) : Option (Ident × List String) :=
  match name.componentsRev.reverse with
  | root :: fields => some (mkIdent root, fields.map toString)
  | [] => none

end Spec

/-- Reject unless a condition holds, naming the condition that failed. -/
syntax "assert " term : doElem

macro_rules
  | `(doElem| assert $condition:term) => do
      let rendered := (condition.raw.reprint.getD "").trimAscii.toString
      `(doElem| if !($condition) then throw $(quote ("assertion failed: " ++ rendered)))

/--
Assign to a field of a mutable binding.

The expansion carries a type ascription, which is what keeps the reassignment it
produces from matching this rule a second time.
-/
syntax (name := doSetField) (priority := high) ident " := " term : doElem

/-- Assign to one element of a sequence held in a field. -/
syntax (name := doSetIndex) (priority := high) ident noWs "[" term "]" " := " term : doElem

macro_rules (kind := doSetField)
  | `(doElem| $target:ident := $value:term) => do
      let some (root, path) := Spec.split target.getId | Macro.throwUnsupported
      `(doElem| $root:ident : _ := $(← Spec.rebuild root path value))

macro_rules (kind := doSetIndex)
  | `(doElem| $target:ident[$index:term] := $value:term) => do
      let some (root, path) := Spec.split target.getId | Macro.throwUnsupported
      let sequence ← path.foldlM (fun t n => `($t.$(mkIdent (.mkSimple n)):ident)) (← `($root))
      let updated ← `(Array.set! $sequence $index $value)
      `(doElem| $root:ident : _ := $(← Spec.rebuild root path updated))

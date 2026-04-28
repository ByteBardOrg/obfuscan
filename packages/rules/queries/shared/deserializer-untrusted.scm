; deserializer-untrusted.scm
;
; Flag any call to a known unsafe deserializer (pickle.loads, BinaryFormatter
; .Deserialize, ObjectInputStream.readObject, Marshal.load, yaml.load, etc.).
; The argument is rarely a literal in real code, so we don't gate on
; #not-literal? — every call site is worth showing in review.
;
; Predicates:
;   - (#match-fqn? @callee deserializers)

(_ @call
  (#match-fqn? @callee deserializers))

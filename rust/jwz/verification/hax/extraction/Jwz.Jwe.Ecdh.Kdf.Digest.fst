module Jwz.Jwe.Ecdh.Kdf.Digest
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// A hash function as the KDF sees it: the digest of the concatenated `parts`,
/// appended to `out`. It is the primitive the proof assumes, not proves.
class t_Digest (v_Self: Type0) = {
  f_append_digest_pre:
      self_: v_Self ->
      parts: t_Array (t_Slice u8) (mk_usize 3) ->
      out: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global
    -> pred: Type0{true ==> pred};
  f_append_digest_post:
      v_Self ->
      t_Array (t_Slice u8) (mk_usize 3) ->
      Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global ->
      Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global
    -> Type0;
  f_append_digest:
      x0: v_Self ->
      x1: t_Array (t_Slice u8) (mk_usize 3) ->
      x2: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global
    -> Prims.Pure (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        (f_append_digest_pre x0 x1 x2)
        (fun result -> f_append_digest_post x0 x1 x2 result)
}

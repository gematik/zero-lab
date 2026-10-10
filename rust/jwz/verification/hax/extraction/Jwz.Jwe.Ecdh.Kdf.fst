module Jwz.Jwe.Ecdh.Kdf
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Jwz.Jwe.Ecdh.Kdf.Digest in
  ()

/// `n` as 4 big-endian bytes.
let be32 (n: u32)
    : Prims.Pure (t_Array u8 (mk_usize 4))
      Prims.l_True
      (ensures
        fun result ->
          let result:t_Array u8 (mk_usize 4) = result in
          result == Jwz.Kdf.Spec.be32 (v n)) =
  let list =
    [
      cast (n >>! mk_i32 24 <: u32) <: u8;
      cast (n >>! mk_i32 16 <: u32) <: u8;
      cast (n >>! mk_i32 8 <: u32) <: u8;
      cast (n <: u32) <: u8
    ]
  in
  FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 4);
  Rust_primitives.Hax.array_of_list 4 list

/// OtherInfo of RFC 7518 §4.6.2: AlgorithmID, PartyUInfo and PartyVInfo, each a
/// 32-bit big-endian length and the data, then SuppPubInfo, the key length in bits.
/// The caller guarantees that every length fits 32 bits.
let other_info (algorithm_id apu apv: t_Slice u8) (key_bits: u32)
    : Prims.Pure (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      (requires
        (Core_models.Slice.impl__len #u8 algorithm_id <: usize) <=.
        (cast (Core_models.Num.impl_u32__MAX <: u32) <: usize) &&
        (Core_models.Slice.impl__len #u8 apu <: usize) <=.
        (cast (Core_models.Num.impl_u32__MAX <: u32) <: usize) &&
        (Core_models.Slice.impl__len #u8 apv <: usize) <=.
        (cast (Core_models.Num.impl_u32__MAX <: u32) <: usize) &&
        ((((Rust_primitives.Hax.Int.from_machine (Core_models.Slice.impl__len #u8 algorithm_id
                    <:
                    usize)
                <:
                Hax_lib.Int.t_Int) +
              (Rust_primitives.Hax.Int.from_machine (Core_models.Slice.impl__len #u8 apu <: usize)
                <:
                Hax_lib.Int.t_Int)
              <:
              Hax_lib.Int.t_Int) +
            (Rust_primitives.Hax.Int.from_machine (Core_models.Slice.impl__len #u8 apv <: usize)
              <:
              Hax_lib.Int.t_Int)
            <:
            Hax_lib.Int.t_Int) +
          (16 <: Hax_lib.Int.t_Int)
          <:
          Hax_lib.Int.t_Int) <=
        (Rust_primitives.Hax.Int.from_machine Core_models.Num.impl_usize__MAX <: Hax_lib.Int.t_Int))
      (ensures
        fun result ->
          let result:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = result in
          Seq.equal result._0 (Jwz.Kdf.Spec.other_info algorithm_id apu apv (v key_bits))) =
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = Alloc.Vec.impl__new #u8 () in
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      out
      (be32 (cast (Core_models.Slice.impl__len #u8 algorithm_id <: usize) <: u32) <: t_Slice u8)
  in
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8 #Alloc.Alloc.t_Global out algorithm_id
  in
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      out
      (be32 (cast (Core_models.Slice.impl__len #u8 apu <: usize) <: u32) <: t_Slice u8)
  in
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8 #Alloc.Alloc.t_Global out apu
  in
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      out
      (be32 (cast (Core_models.Slice.impl__len #u8 apv <: usize) <: u32) <: t_Slice u8)
  in
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8 #Alloc.Alloc.t_Global out apv
  in
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8 #Alloc.Alloc.t_Global out (be32 key_bits <: t_Slice u8)
  in
  out

/// NIST SP 800-56A §5.8.1: for counter = 1 to `reps`, append
/// hash(counter as 32-bit big-endian || Z || OtherInfo) to `out`.
let rounds
      (#v_D: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Jwz.Jwe.Ecdh.Kdf.Digest.t_Digest v_D)
      (hash: v_D)
      (z other_info: t_Slice u8)
      (reps: u32)
      (out: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
    : Prims.Pure (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      Prims.l_True
      (ensures
        fun out_future ->
          let out_future:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = out_future in
          let finished:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = out_future in
          finished == Jwz.Kdf.Spec.rounds hash z other_info (v reps) out) =
  let initial:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Core_models.Clone.f_clone #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      #FStar.Tactics.Typeclasses.solve
      out
  in
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Rust_primitives.Hax.Folds.fold_range (mk_u32 0)
      reps
      (fun out i ->
          let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = out in
          let i:u32 = i in
          out == Jwz.Kdf.Spec.rounds hash z other_info (v i) initial)
      out
      (fun out i ->
          let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = out in
          let i:u32 = i in
          let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
            Jwz.Jwe.Ecdh.Kdf.Digest.f_append_digest #v_D
              #FStar.Tactics.Typeclasses.solve
              hash
              (let list = [be32 (i +! mk_u32 1 <: u32) <: t_Slice u8; z; other_info] in
                FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 3);
                Rust_primitives.Hax.array_of_list 3 list)
              out
          in
          out)
  in
  out

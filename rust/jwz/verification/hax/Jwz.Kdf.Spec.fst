module Jwz.Kdf.Spec
(** The single-step key derivation function of NIST SP 800-56A Rev. 2 §5.8.1, with the
    OtherInfo that RFC 7518 §4.6.2 defines for ECDH-ES, written from those two documents.
    jwz's Concat KDF core (`src/jwe/ecdh.rs`, module `kdf`) states in its `ensures`
    clauses that it computes exactly these functions; F* proves them on the hax
    extraction (`extraction/Jwz.Jwe.Ecdh.Kdf.fst`).

    The hash function H is not specified here: the KDF is proven for every `t_Digest`,
    and the digest itself is RustCrypto's SHA-256, tested against its test vectors. *)
#set-options "--fuel 1 --ifuel 1 --z3rlimit 30"
open FStar.Mul
open Rust_primitives
open Jwz.Jwe.Ecdh.Kdf.Digest

(** SP 800-56A §5.8.1.1: "counter: a 32-bit, big-endian bit string"; RFC 7518 §4.6.2:
    the Datalen of AlgorithmID, PartyUInfo and PartyVInfo, and SuppPubInfo, are 32-bit
    big-endian integers. Byte i is bits 31-8i down to 24-8i. *)
let be32 (n: nat{n < pow2 32}) : t_Array u8 (mk_usize 4) =
  FStar.Math.Lemmas.lemma_div_lt_nat n 32 24;
  let l = [
    mk_u8 (n / pow2 24);
    mk_u8 (n / pow2 16 % pow2 8);
    mk_u8 (n / pow2 8 % pow2 8);
    mk_u8 (n % pow2 8)
  ] in
  assert_norm (List.Tot.length l == 4);
  Rust_primitives.Hax.array_of_list 4 l

(** RFC 7518 §4.6.2: AlgorithmID, PartyUInfo and PartyVInfo are each "Datalen || Data",
    Datalen the length of Data in octets. *)
let datalen_data (d: t_Slice u8 {Seq.length d < pow2 32}) : Seq.seq u8 =
  Seq.append (be32 (Seq.length d)) d

(** RFC 7518 §4.6.2 / SP 800-56A §5.8.1.2: OtherInfo = AlgorithmID || PartyUInfo ||
    PartyVInfo || SuppPubInfo, where SuppPubInfo is keydatalen, the length of the
    derived key in bits, and SuppPrivInfo is empty. *)
let other_info
      (algorithm_id: t_Slice u8 {Seq.length algorithm_id < pow2 32})
      (apu: t_Slice u8 {Seq.length apu < pow2 32})
      (apv: t_Slice u8 {Seq.length apv < pow2 32})
      (key_bits: nat {key_bits < pow2 32})
    : Seq.seq u8 =
  Seq.append (datalen_data algorithm_id)
    (Seq.append (datalen_data apu) (Seq.append (datalen_data apv) (be32 key_bits)))

(** The three parts hashed in round `counter`: counter || Z || OtherInfo. *)
let round_input (counter: nat {counter < pow2 32}) (z other_info: t_Slice u8)
    : t_Array (t_Slice u8) (mk_usize 3) =
  let l = [be32 counter <: t_Slice u8; z; other_info] in
  assert_norm (List.Tot.length l == 3);
  Rust_primitives.Hax.array_of_list 3 l

(** SP 800-56A §5.8.1.1, process steps 4-6: for i = 1 to reps, K(i) = H(counter || Z ||
    OtherInfo) with counter = i, and DerivedKeyingMaterial = K(1) || K(2) || ... ||
    K(reps). Here H(x) appended to `out` is `f_append_digest h x out`, so `rounds h z oi
    k out` is `out` followed by K(1) || ... || K(k), each counter in order. *)
let rec rounds
      (#d: Type0)
      {| i: t_Digest d |}
      (h: d)
      (z other_info: t_Slice u8)
      (k: nat {k < pow2 32})
      (out: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
    : Tot (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) (decreases k) =
  if k = 0
  then out
  else f_append_digest h (round_input k z other_info) (rounds h z other_info (k - 1) out)

(** The two equations of `rounds`, for proofs that run without fuel (hax extractions
    use `--fuel 0`): no rounds leave `out` unchanged, round `k` follows round `k - 1`. *)
let rounds_zero
      (#d: Type0)
      {| i: t_Digest d |}
      (h: d)
      (z other_info: t_Slice u8)
      (out: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
    : Lemma (rounds h z other_info 0 out == out)
      [SMTPat (rounds h z other_info 0 out)] =
  ()

let rounds_step
      (#d: Type0)
      {| i: t_Digest d |}
      (h: d)
      (z other_info: t_Slice u8)
      (k: nat {k > 0 /\ k < pow2 32})
      (out: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
    : Lemma
      (rounds h z other_info k out ==
        f_append_digest h (round_input k z other_info) (rounds h z other_info (k - 1) out))
      [SMTPat (rounds h z other_info k out)] =
  ()

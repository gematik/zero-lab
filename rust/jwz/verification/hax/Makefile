# F* check of jwz's Concat KDF core: the specification from NIST SP 800-56A §5.8.1 and
# RFC 7518 §4.6.2 (Jwz.Kdf.Spec.fst), then the hax extraction (extraction/, written by
# `just verify-hax-jwz`), whose ensures clauses state that it computes the specification.
# Needs F* (FSTAR_HOME, or fstar.exe on PATH) and hax's proof libraries (HAX_HOME, a
# checkout of the hax version in ../stamps/hax.toml).

HAX_HOME ?= $(HOME)/Development/tools/hax
FSTAR_HOME ?= $(HOME)/Development/tools/fstar-v2025.10.06/fstar
FSTAR ?= $(shell command -v fstar.exe 2>/dev/null || echo $(FSTAR_HOME)/bin/fstar.exe)
CACHE ?= .cache

INCLUDES = . extraction \
	$(HAX_HOME)/proof-libs/fstar/core \
	$(HAX_HOME)/proof-libs/fstar/rust_primitives \
	$(HAX_HOME)/hax-lib/proofs/fstar/extraction

FLAGS = $(addprefix --include ,$(INCLUDES)) --cache_dir $(CACHE) --cache_checked_modules \
	--already_cached 'Prims FStar' --z3version 4.13.3 --warn_error -321

ROOTS = extraction/Jwz.Jwe.Ecdh.Kdf.Digest.fst Jwz.Kdf.Spec.fst extraction/Jwz.Jwe.Ecdh.Kdf.fst

.PHONY: verify version clean
verify:
	@mkdir -p $(CACHE)
	@for m in $(ROOTS); do echo "F* $$m"; $(FSTAR) $(FLAGS) $$m || exit 1; done

version:
	@$(FSTAR) --version | head -1

clean:
	rm -rf $(CACHE)

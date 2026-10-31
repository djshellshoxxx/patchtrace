# Reconciliation of the original hidden Clang pilot receipts

Date: 2026-10-31 UTC. Reviewer/rebuilder: `/root/truth_audit`, independent automated agent. Rebuild code checkpoint: `0d14548eef118ac32789da1e410fc1aa6b9f27f2`. No target was executed. Original acceptance, original source/binary review, label files and native result JSON were not edited.

## Finding and actual recovery

The original hidden `msvc-free` O2 acceptance referenced two full build-receipt hashes absent from the initially committed 32-record matrix inventory. That was a real evidence-inventory gap. A search of **81 actual receipt files** (`build.json` and `builds/*.json`) in the external R1 stores found one of the exact original byte sets:

| Side | Referenced receipt SHA-256 | Recovery status |
|---|---|---|
| v1/older | `a30d0f685b2d9f196a04f7e0f6c9ae709c3970d85c7aba5b28e199f2e7c792d3` | Exact bytes found in the controls store's original debug-image `build.json`; copied unchanged and separately reproduced by a fresh build. |
| v2/newer | `15dcb4f875438ef750a9e5444230ade8cb3e3f32773d0fb80ba59304ecbf1a6f` | Historical file not found; a genuinely executed fresh build reproduced the exact previously referenced receipt bytes and all accepted artifact hashes. |

The recovered older file came from `r1-controls-store/images/66908cc4642bb149aad74a23d1e641807edb874da008c3b488f5e74fb462b6ea/build.json`. The pilot store's legacy `build.json` files had been replaced by later O3 records, illustrating the already repaired many-builds-to-one-artifact receipt problem.

The newer record was **not synthesized from labels, guessed flags or a modified O3 receipt**. Current `suite_bases` loaded the actual checked-in source suite, and current `Session.build` compiled both stock O2 source versions in a new external store. The newly emitted full receipt's SHA-256 equals the exact hash recorded in the original acceptance. This closes the missing byte-level reference while preserving the distinction between historical-file recovery and independent fresh reproduction.

The two added files are:

* `build-receipts/a30d0f685b2d9f196a04f7e0f6c9ae709c3970d85c7aba5b28e199f2e7c792d3.json`
* `build-receipts/15dcb4f875438ef750a9e5444230ade8cb3e3f32773d0fb80ba59304ecbf1a6f.json`

The committed receipt inventory therefore increases from **32 to 34** files. Each new filename was checked against the SHA-256 of its exact JSON bytes. `hidden-receipt-reconciliation.json` supplies full artifact/source/recipe bindings and recovery paths.

## Real reproduction and artifact binding

The fresh store is `/workspace/scratch/a55b59b3e326/r1-hidden-receipt-rebuild`. Reproduction used the unmodified current suite sources, stock `msvc-free`, C11, O2, `cflags=[]`, and explicit tool paths matching the original inspection evidence:

```python
names = ('clang', 'lld-link', 'llvm-pdbutil', 'llvm-objdump', 'llvm-nm', 'llvm-strip')
env = dict(os.environ)
for name in names:
    env['PATCHTRACE_KA_' + name.upper().replace('-', '_')] = f'/usr/bin/{name}-18'
tools = probe(env, names=names)
suite, bases = suite_bases(Path('corpus/ours/r1-pilot/defined').resolve())
session = Session(tools, fresh_store)
for version in ('v1', 'v2'):
    result = session.build(bases[version].spec(opt='O2', variant=version))
```

Tool banners were Ubuntu Clang 18.1.3 (1ubuntu1), Ubuntu LLD 18.1.3 and LLVM 18 tools. The source-file hashes are unchanged: v1 `5f0468899fbc95fa4026c3c74b0731a5ab412fe017bbddbed00ad7b0d97acb5f`; v2 `34d8d9f2a1c83c58565ed1885df192c5550e55b9ebb1716d978f8f1c51db27b7`.

Every fresh artifact was rehashed and matched the original acceptance:

| Side | Engine SHA-256 | Debug SHA-256 | PDB SHA-256 |
|---|---|---|---|
| v1 | `36d607e334544fcf98f81f77f46468e559ac849b01f1fd4f930c0a6ab5192294` | `66908cc4642bb149aad74a23d1e641807edb874da008c3b488f5e74fb462b6ea` | `d69c89940cb99ef44ceb750a869206ae781978df36f5bca3ed2ae85d373f7473` |
| v2 | `7b856e5df7916986c3370062990027f4222ae38185006d667a4cd68e365eb5f4` | `6418f198b730f03c7c1a5c70c395e8fee07637fb98e18c509e5205ee1eafb730` | `02ce5f3648be28b3e3b56cb5e7f8550a314c503b95bb229a0ebd65c21f6c35d0` |

Fresh debug/stripped loaded-section equivalence was also verified. Both receipts retain recipe digest `7c7b7d39a28c605d990b52c7d2386168f8adfef803a172daa55aaa7b861f6417`, while their source digests differ as expected between versions. These observations establish exact reproduction of this accepted artifact set, not universal reproducibility for every tool invocation alias or environment.

## Why the matrix records were not substitutes

Matrix records `f4facea3fd4fa5d08ea9223d917be3cb15e0f311c5afa6a7ab93bfa7dac6250b` and `cb7653eb2522abeba4645d21a96f44c9cbb55c7e8a94376e96dfb89de1ae1e84` have the same recipe object, version banners and corresponding source-input digests, but different engine/debug/PDB hashes. Direct comparison found **only those three output-hash fields differ** in each receipt pair. They therefore cannot satisfy the original acceptance's exact artifact binding.

The effective input difference is observable in the PDBs, rather than being unexplained nondeterminism. Running:

```text
/usr/bin/llvm-pdbutil-18 dump --symbols <debug-image-directory>/defined.pdb
```

shows the linker's `S_ENVBLOCK` executable path:

* Original and reproduced artifacts: `/usr/bin/lld-link-18`.
* Matrix artifacts: `/usr/bin/lld-link`.

For each source version, the **entire symbols dump becomes identical after normalizing that one path string**. Corresponding `.text` section raw bytes are exactly equal: v1 section SHA-256 `b11be2989d9310fc2e7a31d1d54f930c8598c1957f26283ceaa073d184574821`; v2 `7709d6dab7e5d42756b0c71ef019436f88d3bad07a9ff14a59a903ec927dc9ef`. The observed PE differences lie in header timestamps and `.rdata` debug identity metadata, alongside the changed PDB. The normalized comparison is of the symbols dump; it does not assert identity of every PDB stream after arbitrary byte replacement.

`build._template` deliberately removes executable `argv[0]` when creating recorded recipe templates. Version banners are recorded, but the actual linker invocation alias is not included in that recipe digest. LLD embeds that alias in debug metadata, so equal recipe/source digests do not establish identical effective debug-metadata inputs. A future provenance enhancement may retain resolved tool binary identity and invocation spelling separately without changing historical recipe digests. No such contract change is introduced here.

More generally, one recipe intentionally applies to multiple source versions. The complete evidence association must include **source inputs/source digest, recipe/tool configuration, and actual engine/debug/PDB hashes**, with the full receipt content hash identifying the assertion. Recipe equality alone is neither a unique build identity nor proof that one receipt substitutes for another accepted artifact set. The fresh versioned-path reproduction and exact hashes above, rather than a recipe-only guess, close the original references.

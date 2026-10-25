# EXTENSION — second reference absorption from `ref/*` (2026-10-25)

This pass read three public Chinese write-ups dropped in `ref/` and absorbed their *mechanisms* into
the files that already own the topics. It did not run any of them. The record exists so a later reader
can tell what changed and on what footing.

## Sources

Three files, described by shape. Titles, authors, product names, package identifiers and every
per-build address are omitted; none was copied onto the tracked surface.

| File | What it is |
|---|---|
| `vm1.md` | A dual-library commercial shell on ARM64: two SOs, one owning Java/ART checks, the other owning an `init_proc` scheduler with inline-shellcode `exit_group`, three watchdog threads and SMC. Covers dump timing, a syscall-level reader, single-predicate patching and a tiered patch order |
| `vm2.md` | A white-box VM protecting one signing routine: threaded-code interpreter, tens of thousands of obfuscated nodes, and a devirtualization to a straight-line `(op, args)` program with constant table, output map and fixed template |
| `vm3.md` | A native signer behind a JNI shim plus an encrypted body: package/signature checks during `JNI_OnLoad`, an emulator used as an oracle, a differential probe that classifies the cipher, an involution wrapper around a standard stream cipher, and Java/Python encoding drift |

All three are **public secondary sources**. Their own claims are `observed` by their authors; nothing
in them was reproduced here. Every absorbed mechanism is therefore `unverified`, and the ordering
judgements built on them are `inferred`. No text, code, key material, offset table or screenshot was
copied.

## What was added

No new reference files. Each mechanism was folded into the file that already owns its topic:

| File | Absorbs | Deliberately does not |
|---|---|---|
| `references/linker-and-soinfo-repair.md` §6.2–6.3 | the dump window that closes inside `JNI_OnLoad` when self-decryption and watchdog startup share it; the raw-syscall reader outside a self-hooked libc; zero-filling unreadable pages so segment offsets survive repair | claim that a dump taken at `android_dlopen_ext` entry is complete; name a specific reader |
| `references/native-tamper-and-suicide.md` §Which site | predicate-first patching (one verdict function versus many kill sites), the tiered grading with the per-tier reason, benign-value selection by caller branch, watchdog enumeration by probe, one tier per run | copy any sample's function table or addresses; assert that a predicate patch covers an unenumerated checker |
| `references/detection-and-anti-analysis.md` §Filter signals | module-filtered signal attribution: ART's implicit `SIGSEGV` on `boot*.oat`/`odex`/JIT pages is the runtime's, and a handler must forward anything outside the target module | claim the discrimination is measured; recommend swallowing runtime signals |
| `references/native-vm-recovery.md` §11 | devirtualization to a runnable program: symbolic input, constant folding, loop/branch elimination, the four artefacts (program, constant table, output map, template), version binding, per-node validation | claim the route works for a VM that reads device state or time; replace the IR-recovery sections |
| `references/protocol-reverse.md` §7 | three black-box probes (header length, prefix XOR, length law), involution-wrapper algebra, fixed-permutation recognition, and the Java-`URLEncoder` / compression-byte drift that decides the last mile | claim any cipher was classified; assume byte-identical compression is required |
| `references/signature-derived-keys.md` §Variant | a certificate-derived salt concatenated *inside* the digest: why black-box hash search cannot find it, how to read the cached buffer, how to verify on three triples, and the per-build consequence | present the captured constant as an algorithm |
| `references/pitfalls.md` P49–P50 | extraction length masquerading as an algorithm gap; an involution wrapper that cancels | duplicate P42's decoder-desync case or the §7 method |

## Registration surface updated

- `evidence/capability-matrix.json`: three rows — `native-dump-window-and-syscall-reader`,
  `whitebox-crypto-devirtualization-to-program`, `cipher-classification-by-differential-probe` — all
  `partial` / `route_measured: false` / `unverified`; two existing rows
  (`native-terminate-path-neutralisation`, `signature-derived-keys`) had their `limits` extended
  rather than duplicated.
- `references/evidence-summary.md`: three rows.
- `references/coverage/route-inventory.md`: three rows.
- `references/coverage-and-limits.md`: three absorbed-route bullets extended.
- `SKILL.md`, `routing.md`, both READMEs: unchanged. No file, script or symptom row was added, so the
  symptom mirror and the reference/script inventories had nothing to learn.

## Deliberately not absorbed

- **Per-build constants and addresses**: function offsets, unified kill-site addresses, the 32-byte
  salt value, the signing prefix and template string, the package identifier, the shell's own
  `sub_*` names. They are only valid for one build and they carry identity.
- **Performance and effort claims** ("1 ms", "days to hours") — no measurement exists here to anchor
  them.
- **The AI-assisted-analysis narrative** in one source: it is advice about tool use, not a reversing
  mechanism, and it is not reproducible as written.
- **Thread and watchdog tables as data.** The *method* (enumerate by probe, then prove the set closed)
  was absorbed; the table itself would invite applying one build's layout to another.

## What would change a label

One cheap experiment per row, all on a device this record never had:

- **Dump window:** dump one protected image at `android_dlopen_ext` entry, repair it, and open it in a
  disassembler with the expected functions present; separately dump inside `JNI_OnLoad` and record
  whether the process survives.
- **Patch grading:** run the same target twice — kill sites only, then the predicate only — and show
  which one survives longer than the observed timer.
- **Devirtualization:** extract one program, run it against a device call on ten inputs, and show
  per-node equality at three checkpoints.
- **Cipher classification:** classify one body with the three probes, then reproduce it and have the
  server accept the request.

Until one of these is recorded, the matrix rows stay `partial` / `unverified` and must not be cited as
support for a claim about a target.

## Gate status

`check_repo.py`, `check_refs.py`, `check_routing.py`, `check_commands.py`, `check_budget.py` and
`pytest -q` were run after the change; the result is in the session record, not in this file. A green
run proves the inventory resolves; it says nothing about whether the mechanisms work.

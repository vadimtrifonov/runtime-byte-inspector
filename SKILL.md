---
name: runtime-byte-inspector
description: Inspect and disassemble AMD64 byte ranges from Windows processes or PE files, and compare saved captures.
---

# Runtime Byte Inspector

Use this skill directory as the working directory.
Requires Windows x64.

## Setup

```powershell
mise trust mise.toml
mise install
mise run setup
```

## Inspect one target

Select exactly one source: `--file`, `--pid`, or `--process`.
`--process` requires an executable name matching exactly one running process.

```powershell
mise run inspector -- inspect --process Example.exe --module Example.dll --rva 0x1000
mise run inspector -- inspect --file "C:\Path\To\image.exe" --rva 0x1000 --before 0
```

| Address | Live process | PE file |
|---|---|---|
| `--rva` | Relative to the process executable, or the module selected by `--module`. | Relative to the PE image. |
| `--va` | Absolute process address, including allocations outside loaded modules. | Preferred-image VA, normalized to an RVA. |

Address and byte-count arguments accept decimal or `0x`-prefixed values.
Code windows default to `--before 32 --after 64`.
The total, `before + 1 + after`, must not exceed **4096 bytes**.
RVA windows are clipped at the selected module's boundaries.
Live VA windows are not clipped to memory regions and must be fully readable; guard and inaccessible pages are rejected.
Use `--before 0` at the beginning of an allocation.
File windows must be backed by the PE headers or one section's raw data; crossing a raw boundary is an error.

### Decoding and references

Decoding assumes an instruction start at the target; preceding bytes are raw context.
Use `--decode-rva` or `--decode-va` to supply an earlier origin in the target's address mode.
The origin must be inside the captured window and at or before the target.
Text output marks an instruction starting at the target with `>>`, or containing it with `*>`.

Decoding stops at a jump, conditional branch, return, trap, invalid/truncated instruction, or the window limit.
Calls retain fallthrough; bytes outside the decoded block remain raw context.

Live decoding reads fixed call/jump pointer cells to resolve their destinations, even with `--follow 0`.
Other fixed memory references report addresses without reading their contents.
Destinations requiring execution state remain `unresolved`.
File inspection decodes references without reading destination memory.

### Pointers and jump following

These options require a live process.

```powershell
mise run inspector -- inspect --pid 12345 --va 0x1C000002000 --before 0 --after 31 --follow 3
mise run inspector -- inspect --pid 12345 --va 0x1C000003000 --pointer --follow 3
```

`--pointer` reads one little-endian **8-byte pointer cell** instead of decoding code.
The cell size is independent of `--before` and `--after`.
Pointer targets cannot request a decoding origin or instruction span.

`--follow N` reads at most N additional code windows: **0** by default, **8** maximum.
Each window starts at its destination and contains `after + 1` bytes.
From a pointer cell, the first hop reads its destination's code.
Following then uses resolved unconditional jumps; calls are not followed and conditional paths are not chosen.
The selected code target must be an instruction start in the chosen decoding, and destinations must be readable and executable.
Cycles, limits, unresolved transfers, and read/decoding failures stop the chain with a recorded reason.

### Instruction spans

```powershell
mise run inspector -- inspect --pid 12345 --rva 0x1000 --span 16 --after 31
```

`--span N` summarizes N bytes starting at the target using the selected decoding origin.
N must be **1..4096** and fit within `after + 1` bytes.
It reports start/end positions as `boundary`, `splits_instruction`, or `not_decoded`, plus overlapping PC/RIP/EIP-relative encoding fields.
Provide trailing bytes with `--after` to decode an instruction crossing the endpoint.
Endpoints beyond the decoded block remain `not_decoded`.
These are encoding facts, not a patch-safety verdict.

## Capture a target list

Use an object with a `targets` array and an optional `description`.
Each entry requires a unique `label` and exactly one `rva` or live `va`.
Numeric fields accept JSON integers or decimal/`0x`-prefixed strings.
See [examples/targets.json](examples/targets.json) and [examples/runtime-targets.json](examples/runtime-targets.json).

| Optional field | Meaning |
|---|---|
| `group`, `notes` | Operator-supplied strings |
| `decode_rva` / `decode_va` | Earlier decoding origin in the target's address mode |
| `kind` | `code` (default) or `pointer` |
| `span` | Instruction-span byte count for a code target |

```powershell
mise run inspector -- capture --pid 12345 --targets "C:\Path\To\targets.json" `
  --output "C:\Path\To\capture.json"
```

Capture accepts the same source, window, and following options as inspection.
Use `--group NAME` to select an exact group; repeat for several groups.
Replacing an existing destination requires `--overwrite`.

Both `inspect` and `capture` accept `--runtime TEXT` and, for live sources, `--patch-state` (`unpatched`, `patched`, or `unknown`; default `unknown`).
These are operator annotations, stored under `annotations` separately from observed identity under `source`.

### Capture format

`inspect --format json` and `capture` emit the same capture format.
`results` contains each target's primary `read` and its decoding or pointer result.
Within each result, additional reads appear under `decode.instructions[].flow.pointer.read` and `follow.hops`.
Successful reads store exact bytes in `bytes_hex` and their starting VA in `start_va`; primary RVA reads also store `start_rva`.
Failed reads have an error and no bytes, including when only part of a requested range was readable.

Reads carry their own start/finish timestamps; captures are sequential with `atomic: false`.
Live locations report module/RVA or allocation/protection details.
Module associations use the inventory taken when the process is opened (`source.module_inventory_at`).
Addresses are `0x`-prefixed strings, counts are integers, and byte strings are packed hexadecimal.

## Compare saved captures

Matching labels are paired by default; unmatched labels are reported separately.

```powershell
mise run inspector -- compare before.json after.json
```

- `--alignment rva` (default): compare overlapping module-relative ranges; requires RVA targets.
- `--alignment target`: align each target at offset zero; required for VA comparisons because absolute addresses are process-specific.

For different labels, supply both `--left-label` and `--right-label`.
Both input paths can refer to the same capture.

```powershell
mise run inspector -- compare capture.json capture.json `
  --left-label function-entry --right-label call-site --alignment target --format text
```

Comparison covers primary target windows or explicitly selected pointer cells, not embedded pointer reads or `follow.hops`.
Reports include source provenance, compared/uncovered byte counts, and contiguous differences.
`windows_equal` is true only when both entire aligned windows are covered and byte-identical.
Difference offsets and overlap bounds use the selected alignment; end bounds are exclusive.

## Output and failures

| Command | stdout |
|---|---|
| `inspect` | Text by default; `--format json` emits a single-target capture |
| `capture` | Absolute path to the saved JSON capture |
| `compare` | JSON report by default; `--format text` selects text |

Diagnostics use stderr.
Invalid input, source-access failures, and publication failures return nonzero.
Read, location-query, and decoding errors also return nonzero, including errors in supporting reads.
Successful reads remain available in the output, and `capture` still saves the results.
Incomplete decoding, unresolved register-dependent targets, and normal following limits are not command failures.

Comparison returns zero for completed reports, including differences, unmatched labels, and unreadable targets.
Invalid comparison input returns nonzero with no stdout.

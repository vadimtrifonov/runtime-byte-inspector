---
name: runtime-byte-inspector
description: Capture and disassemble byte ranges from AMD64 PE files or live Windows processes, and compare saved captures.
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

```powershell
mise run inspector -- inspect --pid 12345 --rva 0x1000
mise run inspector -- inspect --process Example.exe --rva 0x1000
mise run inspector -- inspect --file "C:\Path\To\image.exe" --rva 0x1000 --before 0
```

A process name must match exactly one running process.
`--module Example.dll` selects a different loaded module;
otherwise the process executable is used.

`--rva` is relative to the selected module's base.
`--va` supplies an absolute address instead.
Live sources use the loaded base; files use the PE's preferred image base.

Default windows include 32 bytes before the target and 64 after it.
`--before` and `--after` accept decimal or `0x`-prefixed counts.
The total is `before + 1 + after`,
limited to 4096 bytes and clipped at the module boundaries.

File windows must be backed by the PE headers or one section's raw data.
Crossing a section's raw boundary is an error.

### Decoding

Decoding begins at the target by default; preceding bytes are raw context.
Use `--decode-rva` when a different instruction start is known.
It must be inside the captured window, at or before the target.

In text output, `>>` means the target starts an instruction in that decoding;
`*>` means it falls inside one.
A patch can change instruction lengths,
so an original instruction start may lie inside a patched instruction.

Text output marks the undecoded tail when decoding stops at invalid or truncated bytes.

## Capture a target list

Use a JSON object with a `targets` array; see [examples/targets.json](examples/targets.json).
Each target requires a unique `label` and an `rva`.
RVAs accept JSON integers or decimal/`0x`-prefixed strings.
Optional `group` and `notes` fields are strings;
`decode_rva` optionally sets the decoding origin.
An optional top-level `description` identifies the module/build or investigation.

```powershell
mise run inspector -- capture --pid 12345 `
  --targets "C:\Path\To\targets.json" `
  --patch-state unpatched --runtime "Example 1.0" `
  --output "C:\Path\To\capture.json"
```

Capture accepts the same file/process selection and window sizes as inspection.
Use `--group NAME` to select an exact group; repeat for several groups.
Replacing an existing destination requires `--overwrite`.

### Annotations

Both `inspect` and `capture` accept operator annotations:

- `--patch-state`: `unpatched`, `patched`, or `unknown` (default), for live targets.
- `--runtime`: a runtime/build description.

They are saved under `annotations`, separately from observed identity under `source`.

### Capture JSON

`inspect --format json` and `capture` produce the same capture format.
Each entry in `results` retains its `target` definition and `read` result, even on failure.
Successful reads include `decode`; failed reads omit it.
Reads are sequential; `started_at` and `finished_at` bound the batch.
Addresses are `0x`-prefixed strings, byte counts are JSON integers,
and byte strings are packed hexadecimal.

## Compare saved captures

Matching labels are paired by default; unmatched labels are reported separately.
Inputs can come from different modules or builds.

```powershell
mise run inspector -- compare before.json after.json
```

For different labels, select exactly one result on each side.
Both paths can refer to the same capture.

```powershell
mise run inspector -- compare capture.json capture.json `
  --left-label function-entry --right-label call-site `
  --format text
```

Alignment is explicit:

- `--alignment rva` (default): compare the overlapping module-RVA ranges.
- `--alignment target`: treat each selected target as offset zero
  and compare the overlapping relative ranges.

Reports include source provenance, compared and uncovered byte counts,
contiguous difference runs, and `windows_equal`.
That flag is true only when both entire aligned windows are covered and byte-identical.

Difference `offset` and overlap bounds use the chosen alignment's coordinates.
End bounds are exclusive.
Comparison uses raw bytes and rejects inconsistent byte ranges or duplicate labels.

## Output and failures

| Command | stdout |
|---|---|
| `inspect` | Text by default; `--format json` emits a single-target capture |
| `capture` | Absolute path to the saved JSON capture |
| `compare` | JSON report by default; `--format text` selects text |

Diagnostics use stderr.
Invalid input, source-access failures, and publication failures return nonzero.
Per-target read or decoding errors also return nonzero,
but `capture` still saves the results.
Failed reads have no captured bytes; decoding errors retain the read bytes.
Incomplete decoding alone does not fail the command.

Comparison returns zero for completed reports, including differences,
unmatched labels, and unreadable targets.
Invalid comparison input produces no stdout.

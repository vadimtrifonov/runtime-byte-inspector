# Runtime Byte Inspector

Runtime Byte Inspector is a command-line tool for inspecting x86-64 code in PE files and running Windows processes.
It reads selected byte ranges and displays their disassembly.
Live inspection shows the code present after loading or runtime patching, which can differ from the executable on disk.

Live inspection is read-only and includes memory outside loaded executables and DLLs, such as trampolines.
It can resolve pointers and follow jump chains between these locations.

## Targets and captures

A **target** is an address chosen for inspection.
It can be an offset within an executable or DLL's loaded image (RVA), or an absolute live-process address (VA).
A **target list** is a JSON file of labeled targets for inspecting several sites together.
The labels identify the sites when comparing captures.
See the [example target list](examples/targets.json) and [runtime examples](examples/runtime-targets.json).

A **capture** saves the bytes and inspection results for one or more targets, including disassembly, pointer values, and any followed code.
Saved JSON captures preserve source information and read times, so the results remain available for review after the process exits.
Live reads are sequential rather than an atomic snapshot; failed reads are recorded alongside successful results.

## Commands

| Command | Input | Output |
|---|---|---|
| `inspect` | One address in a PE file or running process | Bytes and disassembly or pointer values; text or JSON |
| `capture` | A target list and a PE file or running process | One saved JSON capture for the selected targets |
| `compare` | Two saved captures | Byte differences, coverage, and labels present in only one capture |

For a before/after check, capture the same labeled sites in each setup, then compare the saved files.
Comparisons pair matching labels by default or use an explicitly selected pair.
They compare the targets' own byte ranges; supporting pointer reads and followed code are saved but are not automatically paired.

## Getting started

Requires Windows x64 and [mise](https://mise.jdx.dev/).
See [SKILL.md](SKILL.md) for setup and operating commands.

## Development

```powershell
mise run test
mise run check
mise run format
```

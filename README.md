# Runtime Byte Inspector

Runtime Byte Inspector is a command-line tool for inspecting x86-64 executables and DLLs.
It reads byte ranges from PE files or modules in a running Windows process
and displays their disassembly.
Live inspection shows the code present after loading or runtime patching,
which can differ from the executable on disk.

## Targets and captures

A **target** is an address chosen for inspection.
A **target list** is a JSON file containing labeled targets,
each with an RVA: an offset from the beginning of the executable or DLL in memory.
Optional groups and notes organize the list.
See the [example target list](examples/targets.json) for the format.

A **capture** records the bytes read around one or more targets.
Saved JSON captures separate source information, requested settings, operator annotations,
and each target's read and decoding results.
Raw bytes, disassembly, start and finish times, and tool and decoder details
remain available for review after the process exits.

## Commands

| Command | Input | Output |
|---|---|---|
| `inspect` | One address in a PE file or running process | Bytes and disassembly, or a JSON capture |
| `capture` | A target list and a PE file or running process | One saved JSON capture containing results for the selected targets |
| `compare` | Two saved captures | Byte differences, coverage, and labels present in only one capture |

For a before/after check, capture the same target list in each setup,
then compare the saved files.

Comparisons pair matching labels by default and align the captured bytes
by module-relative address (RVA) or by offsets from the selected targets.

## Getting started

Requires Windows x64 and [mise](https://mise.jdx.dev/).
See [SKILL.md](SKILL.md) for setup and operating commands.

## Development

```powershell
mise run test
mise run check
mise run format
```

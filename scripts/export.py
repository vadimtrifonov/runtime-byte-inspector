from pathlib import Path

from .capture import write_bytes
from .compare import load_capture
from .targets import integer


def export_capture(path: Path, label: str, output: Path, overwrite: bool = False) -> dict:
    if output.exists() and output.samefile(path):
        raise ValueError("Export destination must not be the input capture")
    metadata, records = load_capture(path)
    record = next((record for record in records if record.label == label), None)
    if record is None:
        raise ValueError(f"Label {label!r} not found in '{path}'")
    if record.raw is None:
        raise ValueError(f"Capture read {label!r} failed: {record.error['message']}")
    report = {
        "capture": str(path.resolve()),
        "label": label,
        "output": str(output.resolve()),
        "byte_count": len(record.raw),
    }
    if record.rva is not None:
        module = metadata["source"]["module"]
        base = integer(module["base_address"], "source.module.base_address")
        start = base + record.rva - record.before
        report.update(
            module_base=hex(base),
            module_size=integer(module["image_size"], "source.module.image_size"),
        )
    else:
        start = record.va - record.before
    report["start_va"] = hex(start)
    write_bytes(output, record.raw, overwrite)
    return report

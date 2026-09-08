from __future__ import annotations


def location_text(location: dict) -> str:
    va = location["va"]
    if "error" in location:
        return f"{va} (location error: {location['error']['message']})"
    module = location.get("module")
    if module:
        return f"{module['name']}+{location['rva']} ({va})"
    region = location.get("region", {})
    return f"{va} ({region.get('kind', 'unknown')} allocation {region.get('allocation_base', 'unknown')})"


def render_result(result: dict) -> list[str]:
    target = result["target"]
    location = result.get("location")
    lines = [f"target {target['label']}: " + (location_text(location) if location else str(target))]
    if location and "region" in location:
        region = location["region"]
        lines.append(
            f"  memory: {region['state']}, protection={region['protection']}, "
            f"readable={region['readable']}, executable={region['executable']}"
        )
    read = result["read"]
    if read["status"] != "ok":
        lines.append(f"  read error: {read['error']['message']}")
        return lines
    start = int(read["start_va"], 0)
    blob = bytes.fromhex(read["bytes_hex"])
    lines.append("\nCaptured bytes (VA):")
    for offset in range(0, len(blob), 16):
        lines.append(f"  {start + offset:016X}  {blob[offset : offset + 16].hex(' ').upper()}")
    if "pointer" in result:
        pointer = result["pointer"]
        lines.append("\nPointer destination: " + location_text(pointer["destination"]))
        return lines
    decoded = result["decode"]
    if decoded["status"] == "error":
        lines.append(f"\nDecode error: {decoded['error']['message']}")
        return lines
    lines.append(
        f"\nDecode from {decoded['start_va']} ({decoded['origin_basis']}): "
        f"{decoded['status']} ({decoded['stop_reason']})"
    )
    target_va = int(location["va"], 0)
    for instruction in decoded["instructions"]:
        va = int(instruction["va"], 0)
        marker = ">>" if va == target_va else ("*>" if va < target_va < va + instruction["size"] else "  ")
        lines.append(
            f"{marker} {va:016X}  {instruction['bytes_hex']:<30} "
            f"{instruction['mnemonic']} {instruction['operands']}".rstrip()
        )
        flow = instruction["flow"]
        if flow.get("resolution") == "pointer":
            pointer = flow.get("pointer")
            if pointer is None:
                lines.append(f"      pointer cell {flow['pointer_va']} (not read from file)")
            else:
                cell = pointer["read"]
                value = (
                    cell["bytes_hex"] if cell["status"] == "ok" else "read error: " + cell["error"]["message"]
                )
                lines.append(f"      pointer cell {flow['pointer_va']}: {value}")
        if "destination" in flow:
            lines.append("      destination: " + location_text(flow["destination"]))
        elif flow.get("resolution") == "unresolved":
            lines.append("      target unresolved: requires execution state")
        for operand in instruction["operand_details"]:
            if "location" in operand:
                lines.append("      referenced address: " + location_text(operand["location"]))
    end = int(decoded["start_va"], 0) + decoded["decoded_bytes"]
    if end < start + len(blob):
        label = "undecoded" if decoded["status"] == "incomplete" else "raw context after block"
        lines.append(f"{label} from {end:#x}: {blob[end - start :].hex().upper()}")
    if "span" in result:
        span = result["span"]
        lines.append(f"\nSpan {span['size']} bytes: start={span['start_status']}, end={span['end_status']}")
        for instruction in span["relative_instructions"]:
            lines.append(
                f"  {instruction['va']}: " + ", ".join(field["kind"] for field in instruction["fields"])
            )
        lines.append("  Encoding facts only, not a patch-safety verdict.")
    return lines


def render_inspection(capture: dict) -> str:
    source = capture["source"]
    module = source["module"]
    lines = [
        f"source: {source['kind']} {source.get('process', module)['path']}",
        f"selected module: {module['name']} base={module['base_address']}",
    ]
    if "process" in source:
        lines.append(f"pid: {source['process']['pid']}")
        lines.append(f"patch state (annotation): {capture['annotations']['patch_state']}")
    result = capture["results"][0]
    lines.extend(render_result(result))
    if "follow" in result:
        follow = result["follow"]
        for index, hop in enumerate(follow["hops"], 1):
            lines.append(f"\nFollow hop {index}:")
            lines.extend(render_result(hop))
        lines.append(f"\nFollowing stopped: {follow['stop_reason']}")
        if "stopped_at" in follow:
            lines.append("  " + location_text(follow["stopped_at"]))
    return "\n".join(lines)

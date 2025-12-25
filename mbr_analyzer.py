#!/usr/bin/env python3
import argparse
import os
import struct
import sys
from typing import List, Dict, Any


def read_mbr(path: str) -> bytes:
    """Read first 512 bytes from given file."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"File not found: {path}")

    with open(path, "rb") as f:
        data = f.read(512)

    if len(data) < 512:
        raise ValueError(f"File is too small to contain a full MBR (only {len(data)} bytes)")

    return data


def parse_partition_entry(entry: bytes) -> Dict[str, Any]:
    """Parse a 16-byte MBR partition entry into a friendly dict."""
    if len(entry) != 16:
        raise ValueError("Partition entry must be 16 bytes")

    status, first_head, first_sector, first_cylinder, ptype, \
        last_head, last_sector, last_cylinder, lba_start, num_sectors = struct.unpack(
            "<BBBBBBBBII", entry
        )

    return {
        "status": status,
        "bootable": (status == 0x80),
        "partition_type": ptype,
        "first_chs": (first_head, first_sector, first_cylinder),
        "last_chs": (last_head, last_sector, last_cylinder),
        "lba_start": lba_start,
        "num_sectors": num_sectors,
    }


def analyze_mbr(mbr: bytes) -> Dict[str, Any]:
    report: Dict[str, Any] = {}
    issues: List[str] = []      # BROKEN-class findings
    warnings: List[str] = []    # suspicious / misconfig

    sig = mbr[510:512]
    valid_signature = (sig == b"\x55\xaa")
    if not valid_signature:
        issues.append(f"Invalid signature: expected 0x55AA, found 0x{sig[0]:02X} 0x{sig[1]:02X}")

    report["signature_valid"] = valid_signature
    report["signature_hex"] = f"0x{sig[0]:02X}{sig[1]:02X}"

    partitions: List[Dict[str, Any]] = []
    for i in range(4):
        offset = 446 + i * 16
        entry_bytes = mbr[offset: offset + 16]
        part = parse_partition_entry(entry_bytes)
        part["index"] = i
        partitions.append(part)

    report["partitions"] = partitions

    bootable_count = sum(1 for p in partitions if p["bootable"])
    if bootable_count > 1:
        warnings.append(f"{bootable_count} active (bootable) partitions detected (expected at most 1).")

    for p in partitions:
        if p["partition_type"] != 0x00 and p["num_sectors"] == 0:
            warnings.append(
                f"Partition {p['index']} has non-zero type 0x{p['partition_type']:02X} but zero sectors."
            )

        # alignment / suspicious LBA start (common modern alignment is 2048)
        if p["partition_type"] != 0x00 and p["num_sectors"] > 0:
            if p["lba_start"] < 63:
                warnings.append(
                    f"Partition {p['index']} starts at LBA {p['lba_start']} (very low; may be legacy/weird alignment)."
                )

    used_parts = [p for p in partitions if p["partition_type"] != 0x00 and p["num_sectors"] > 0]
    used_parts_sorted = sorted(used_parts, key=lambda p: p["lba_start"])
    for i in range(1, len(used_parts_sorted)):
        prev = used_parts_sorted[i - 1]
        curr = used_parts_sorted[i]
        prev_end = prev["lba_start"] + prev["num_sectors"] - 1
        if curr["lba_start"] <= prev_end:
            issues.append(
                f"Partition {curr['index']} (LBA {curr['lba_start']}) overlaps with "
                f"partition {prev['index']} (end LBA {prev_end})."
            )

    # status decision
    if issues:
        status = "BROKEN"
    elif warnings:
        status = "WARN"
    else:
        status = "OK"

    report["issues"] = issues
    report["warnings"] = warnings
    report["status"] = status
    report["looks_broken"] = (status == "BROKEN")
    return report


def format_partition_info(p: Dict[str, Any]) -> str:
    """Return a human-readable summary for a partition entry."""
    if p["partition_type"] == 0x00 and p["num_sectors"] == 0 and p["lba_start"] == 0:
        return f"Partition {p['index']}: unused"

    size_sectors = p["num_sectors"]
    size_bytes = size_sectors * 512
    size_mb = size_bytes / (1024 * 1024)

    return (
        f"Partition {p['index']}:\n"
        f"  Bootable: {'Yes' if p['bootable'] else 'No'} (status=0x{p['status']:02X})\n"
        f"  Type: 0x{p['partition_type']:02X}\n"
        f"  LBA start: {p['lba_start']}\n"
        f"  Sectors: {size_sectors} (~{size_mb:.2f} MiB assuming 512B sectors)\n"
        f"  First CHS: {p['first_chs']}\n"
        f"  Last  CHS: {p['last_chs']}"
    )


def print_report(report: Dict[str, Any], path: str) -> None:
    print(f"=== MBR Analysis for: {path} ===")
    print(f"Signature: {report['signature_hex']} "
          f"({'valid' if report['signature_valid'] else 'INVALID'})\n")

    print("Partition table:")
    for p in report["partitions"]:
        print(format_partition_info(p))
        print()

    if report["issues"]:
        print("Issues detected:")
        for issue in report["issues"]:
            print(f"  - {issue}")
    else:
        print("No obvious issues detected.")

    print(f"\nLooks broken? {'YES' if report['looks_broken'] else 'No (seems OK-ish)'}")


def main():
    parser = argparse.ArgumentParser(
        description="Simple MBR analyzer: checks signature and partition table."
    )
    parser.add_argument(
        "image",
        help="Path to disk image or file containing an MBR (first 512 bytes).",
    )
    args = parser.parse_args()

    try:
        mbr = read_mbr(args.image)
        report = analyze_mbr(mbr)
        print_report(report, args.image)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

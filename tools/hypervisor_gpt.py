"""Build one independently signed Hypervisor GPT slot as a new regular disk image."""

import hashlib
from uuid import UUID, uuid5

from host_storage import DATA_PARTITION
from image_verity import extract_partition, read_layout
from runtime_boot import BOOT_EFI, PARTITIONS as CORE_PARTITIONS, build_uki, run


MANIFEST = "hypervisor-slot"
SUPPORT = "hypervisor-slot-support-v1"
ROOT_SIGNATURE = "hypervisor-root.p7s"
TYPE_NAMESPACE = UUID("e43aab67-9a8a-417a-bf06-4f62fbeccd11")
PARTITIONS = {
    "esp": CORE_PARTITIONS["esp"],
    "core": CORE_PARTITIONS["root"],
    "core_verity": CORE_PARTITIONS["verity"],
    **{name: str(uuid5(TYPE_NAMESPACE, name)) for name in ("runtime", "runtime_verity", "guest", "guest_verity")},
}


def approval(identifier, prepared):
    if identifier.int == 0:
        raise ValueError("Hypervisor slot UUID must be nonzero")
    ids = {name: str(uuid5(identifier, name)) for name in PARTITIONS}
    manifest = "FVCA-HYPERVISOR-SLOT-1\n" + "".join(f"{name}={part}\n" for name, part in ids.items())
    return ids, ((MANIFEST, manifest.encode("ascii")), (ROOT_SIGNATURE, (prepared / "root.p7s").read_bytes()))


def command_line(cmdline, ids):
    devices = {"systemd.verity_root_data": ids["core"], "systemd.verity_root_hash": ids["core_verity"]}
    arguments = cmdline.split()
    if any(arg.partition("=")[0] in devices for arg in arguments):
        raise ValueError("shared core already configures explicit verity devices")
    arguments = [arg for arg in arguments if not arg.startswith("systemd.verity_root_options=")]
    return " ".join((*arguments,
                     *(f"{name}=/dev/disk/by-partuuid/{part}" for name, part in devices.items()),
                     f"systemd.verity_root_options=panic-on-corruption,root-hash-signature=/usr/lib/fvca/{ROOT_SIGNATURE}"))


def verify_readback(image, types, ids, sources, sector_size):
    sector, parts = read_layout(image, types, sector_size=sector_size)
    with image.open("rb") as stream:
        for name, source in sources.items():
            part = parts[name]
            length = part["size"] * sector
            if part["uuid"].lower() != ids[name] or length != source.stat().st_size:
                raise ValueError(f"installed Hypervisor slot has an unexpected {name} partition boundary")
            stream.seek(part["start"] * sector)
            installed = hashlib.sha256()
            while length:
                data = stream.read(min(length, 1024 * 1024))
                if not data:
                    raise ValueError(f"incomplete installed {name} partition")
                installed.update(data)
                length -= len(data)
            with source.open("rb") as expected:
                if installed.digest() != hashlib.file_digest(expected, "sha256").digest():
                    raise ValueError(f"installed {name} partition differs from its authorized bytes")
    return sector, parts


def write_layout(work, name, args, uki, sources, ids, *, image_size=None):
    types = PARTITIONS | (DATA_PARTITION if "host_data" in sources else {})
    logical_sector = args.gpt_sector_size or 4096
    definitions = work / f"{name}.repart.d"
    definitions.mkdir()
    for index, (partition, image) in enumerate(sources.items()):
        size = image.stat().st_size
        if size == 0 or size % 4096:
            raise ValueError(f"Hypervisor slot source {partition} is not 4 KiB aligned")
        (definitions / f"{index:02}.conf").write_text(
            f"[Partition]\nType={types[partition]}\nUUID={ids[partition]}\nLabel=fvca-{partition}\n"
            f"SizeMinBytes={size}\nSizeMaxBytes={size}\nCopyBlocks={image}\n", encoding="utf-8"
        )
    disk = work / f"{name}.raw"
    run("systemd-repart", "--empty=create", "--offline=yes", f"--size={image_size or 'auto'}", "--dry-run=no",
        f"--sector-size={logical_sector}", f"--seed={args.gpt_slot}", f"--definitions={definitions}", disk)
    if image_size is not None and image_size != disk.stat().st_size:
        raise ValueError("the integrated image does not match the requested disk capacity")
    sector, parts = verify_readback(disk, types, ids, sources, logical_sector)
    loader = work / f"{name}.efi"
    run("mcopy", "-i", f"{disk}@@{parts['esp']['start'] * sector}", BOOT_EFI, loader)
    if loader.read_bytes() != uki.read_bytes():
        raise ValueError("installed ESP has a different UKI")
    print(f"FVCA Hypervisor GPT slot verified ESP {ids['esp']}")
    return disk


def pack(args, work, ids, cmdline, uname, composition, pcr_options, *, data=None):
    uki = build_uki(args, work, command_line(cmdline, ids), uname, composition, pcr_options)
    run("sbverify", "--cert", args.boot_certificate, uki)
    sector, core = read_layout(args.core, CORE_PARTITIONS)
    partition_work = work / "slot-partitions"
    partition_work.mkdir()
    for origin, name in (("root", "core"), ("verity", "core_verity")):
        extract_partition(args.core, core[origin], sector, partition_work / name)
    esp = partition_work / "esp"
    logical_sector = args.gpt_sector_size or 4096
    # FAT32 requires at least 65,525 clusters. Keep space for two FATs and the UKI.
    esp_bytes = max(272 * 1024**2, uki.stat().st_size + 16 * 1024**2)
    esp_kib = 4 * ((esp_bytes + 4095) // 4096)
    run("mkfs.fat", "-C", "-F", "32", "-S", str(logical_sector), "-s", "1", esp, str(esp_kib))
    run("mmd", "-i", esp, "::/EFI", "::/EFI/BOOT")
    run("mcopy", "-i", esp, uki, BOOT_EFI)

    sources = {
        "esp": esp, "core": partition_work / "core", "core_verity": partition_work / "core_verity",
        "runtime": work / "runtime/root", "runtime_verity": work / "runtime/verity",
        "guest": work / "guest/root", "guest_verity": work / "guest/verity",
    }
    immutable = None
    if args.immutable_output is not None:
        immutable = write_layout(work, "immutable-slot", args, uki, sources, ids)
    if data is not None:
        identifier, payload = data
        if identifier in ids.values():
            raise ValueError("the Host data UUID collides with an immutable slot partition")
        ids = ids | {"host_data": identifier}
        sources["host_data"] = payload
    disk = write_layout(work, "hypervisor-slot", args, uki, sources, ids, image_size=args.gpt_disk_bytes)
    return disk, immutable

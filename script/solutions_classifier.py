from collections import defaultdict
from pathlib import Path
import json
from argparse import ArgumentParser

test_dir = "test"
# Check if a different test dir was passed as argument
import sys

sys.path.append(str(Path(__file__).parent))

from parse_mbox import parse_mailbox


def extract_command(actual_data: Path):
    # This is not correct for arbitrary run configs but works for mine
    with actual_data.open("rb") as f:
        data = f.read()
    # data = data[4:]
    return (
        parse_mailbox(int.from_bytes(data[:4], "little")),
        int.from_bytes(data[4:8], "little"),
        int.from_bytes(data[8:12], "little"),
    )


parser = ArgumentParser(description="Plot libafl log file")
parser.add_argument(
    "test_dir",
    type=str,
    help="Path to the run to analyze",
)
group = parser.add_mutually_exclusive_group()
group.add_argument(
    "-l",
    "--file_list",
    action="store_true",
    required=False,
    help="Should we generate a rsync transfer list",
)
group.add_argument(
    "-b",
    "--binary",
    action="store_true",
    required=False,
    help="Also parse the associated input files to get initial values",
)
args = parser.parse_args()
# Path to the directory containing youre solutions
directory_path = (
    Path(__file__).parents[1] / "amd_sp" / "runs" / args.test_dir / "solutions"
)
if not args:
    print(f"Looking for metadata files in {directory_path}")

write_locations = defaultdict(lambda: defaultdict(set))
read_locations = defaultdict(lambda: defaultdict(set))

exceptions = defaultdict(lambda: defaultdict(set))

crashing_commands = set()
ptr_set = set()
# Iterate over all files that match the .<hash>.metadata pattern
for file_path in directory_path.glob(".*.metadata"):
    try:
        with file_path.open("r") as f:
            name = file_path.name
            # Deduplicate the name for entries with the same hash
            first_hash = name.removeprefix(".").removesuffix(".metadata")
            first_hash = first_hash.split("_")[0]
            actual_data = directory_path / first_hash
            data = json.load(f)
            # Navigate to the AccessObserverMetadata array and check if 'caught_write' is not null
            meta_map = data.get("metadata", {}).get("map", {})
            access_observer = meta_map.get(
                "libasp::bindings::AccessObserverMetadata", [None, None]
            )[1]
            if access_observer is None:
                # Fallback for older results
                access_observer = meta_map.get(
                    "libasp::bindings::WriteCatcherMetadata", [None, None]
                )[1]

            write_caught = access_observer.get("caught_write")
            read_caught = access_observer.get("caught_read")

            if write_caught is not None:
                write_location, write_pc = write_caught
                if args.binary:
                    (command, upper, lower) = extract_command(actual_data)
                    crashing_commands.add(hex(command.CommandId))
                    write_locations[write_pc][command.CommandId].add(actual_data)
                else:
                    write_locations[write_pc][write_location].add(actual_data)
            if read_caught is not None:
                read_location, read_pc = read_caught
                if args.binary:
                    (command, upper, lower) = extract_command(actual_data)
                    crashing_commands.add(hex(command.CommandId))
                    read_locations[read_pc][command.CommandId].add(actual_data)
                else:
                    read_locations[read_pc][read_location].add(actual_data)
            exception_meta = meta_map.get(
                "libasp::exception_handler::ExceptionHandlerMetadata", [None, None]
            )[1]
            if exception_meta is not None:
                exception_type = exception_meta.get("triggered_exception")
                if exception_type is not None:
                    exceptions[exception_type][exception_meta["registers"]["lr"]].add(
                        actual_data
                    )
                    if args.binary:
                        (command, upper, lower) = extract_command(actual_data)
                        assert command.CommandId == 0x5
                    misc_meta = meta_map.get(
                        "libasp::emulator_module::MiscMetadata", [None, None]
                    )[1]
                    if misc_meta is not None:
                        mailbox_meta = misc_meta.get("mailbox_values")
                        full_ptr = mailbox_meta["ptr_lower"]
                        full_ptr |= mailbox_meta["ptr_higher"] << 32
                        # DATAB is actually triggered by unaligned access
                        assert full_ptr % 4 != 0
                        ptr_set.add(full_ptr & 0xF)

            # Document all successful commands
            if args.binary:
                if (
                    write_caught is not None
                    or read_caught is not None
                    or exception_meta is not None
                    or True
                ):
                    (command, upper, lower) = extract_command(actual_data)
                    crashing_commands.add(hex(command.CommandId))

    except (json.JSONDecodeError, KeyError, IndexError, AttributeError) as e:
        print(
            f"Could not process {file_path}, possibly due to malformed JSON or unexpected structure. error: {e}"
        )
# python ./script/metadata_classifier.py tompute true > file_list.txt
# rsync -av -e ssh --files-from=file_list.txt amd_sp/runs/tompute/solutions tompute:~/projects/ASPFuzz/amd_sp/bins/seed
if args.file_list:
    for per_write_location in write_locations.values():
        for entries in per_write_location.values():
            for entry in entries:
                print(entry.name)
    for per_pc in read_locations.values():
        for entries in per_pc.values():
            for entry in entries:
                print(entry.name)
    exit(0)

# Print matching files
for pc, per_write_loc in write_locations.items():
    for write_loc, entries in per_write_loc.items():
        print(
            f"Write \t PC: {hex(pc)}\t {'Location' if not args.binary else 'CommandID'}: \t {hex(write_loc)}\t count: {len(entries)}\t Exemplar: {entries.pop()}"
        )

for pc, per_read_loc in read_locations.items():
    for read_loc, entries in per_read_loc.items():
        print(
            f"Read \t PC: {hex(pc)}\t {'Location' if not args.binary else 'CommandID'}: \t {hex(read_loc)}\t count: {len(entries)}\t Exemplar: {entries.pop()}"
        )

for exception, per_lr in exceptions.items():
    for lr, entries in per_lr.items():
        print(
            f"Exception: \t {exception} \t LR: {lr}\t count: {len(entries)}\t Exemplar: {entries.pop()}"
        )
if args.binary:
    print(f"Crashing commands: {crashing_commands}")
    print(f"Last bytes for all pointers in DATAB: {[bin(x) for x in sorted(ptr_set)]}")

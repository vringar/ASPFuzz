from collections import defaultdict
from pathlib import Path
import json

test_dir = "test"
# Check if a different test dir was passed as argument
import sys

if len(sys.argv) > 1:
    test_dir = sys.argv[1]
# Path to the directory containing your .<hash>.metadata files
directory_path = Path(__file__).parents[1] / "amd_sp" / "runs" / test_dir / "solutions"
print(f"Looking for metadata files in {directory_path}")

write_locations = defaultdict(lambda: defaultdict(list))
read_locations = defaultdict(lambda: defaultdict(list))

exceptions = defaultdict(lambda: defaultdict(list))

real_mailbox_ptr = []
# Iterate over all files that match the .<hash>.metadata pattern
for file_path in directory_path.glob(".*.metadata"):
    try:
        with file_path.open("r") as f:
            data = json.load(f)
            # Navigate to the WriteCatcherMetadata array and check if 'caught_write' is not null
            meta_map = data.get("metadata", {}).get("map", {})
            write_catcher = meta_map.get(
                "libasp::bindings::WriteCatcherMetadata", [None, None]
            )[1]
            write_caught = write_catcher.get("caught_write")
            read_caught = write_catcher.get("caught_read")

            if write_caught is not None:
                write_location, write_pc = write_caught
                write_locations[write_location][write_pc].append(file_path)
            if read_caught is not None:
                read_location, read_pc = read_caught
                read_locations[read_location][read_pc].append(file_path)

            exception_meta = meta_map.get(
                "libasp::exception_handler::ExceptionHandlerMetadata", [None, None]
            )[1]
            if exception_meta is not None:
                exception_type = exception_meta.get("triggered_exception")
                if exception_type is not None:
                    exceptions[exception_type][
                        exception_meta["registers"]["lr"]
                    ].append(file_path)
            mailbox_meta = meta_map.get(
                "libasp::emulator_module::MiscMetadata", [None, None]
            )[1]
            if mailbox_meta is not None:
                ptr_lower = mailbox_meta.get("ptr_lower", 0)
                ptr_higher = mailbox_meta.get("ptr_higher", 0)
                if ptr_lower != 0 or ptr_higher != 0:
                    real_mailbox_ptr.append((ptr_lower, ptr_higher))

    except (json.JSONDecodeError, KeyError, IndexError, AttributeError):
        print(
            f"Could not process {file_path}, possibly due to malformed JSON or unexpected structure."
        )

# Print matching files
for write_loc, per_pc in write_locations.items():
    for pc, entries in per_pc.items():
        print(
            f"Write location: \t {hex(write_loc)}\t PC: {hex(pc)}\t count: {len(entries)}\t Exemplar: {entries[0]}"
        )

for read_loc, per_pc in read_locations.items():
    for pc, entries in per_pc.items():
        print(
            f"Read location: \t\t {hex(read_loc)}\t PC: {hex(pc)}\t count: {len(entries)}\t Exemplar: {entries[0]}"
        )

for exception, per_lr in exceptions.items():
    for lr, entries in per_lr.items():
        print(
            f"Exception: \t {exception} \t LR: {lr}\t count: {len(entries)}\t Exemplar: {entries[0]}"
        )

print("length:", len(real_mailbox_ptr))
for ptr in real_mailbox_ptr:
    print(f"Mailbox ptr: \t {ptr[0]:#x} {ptr[1]:#x}")

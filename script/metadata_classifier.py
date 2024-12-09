from collections import defaultdict
from pathlib import Path
import json

test_dir = "test"
# Check if a different test dir was passed as argument
import sys

valuable_crashes = False
if len(sys.argv) > 1:
    test_dir = sys.argv[1]
if len(sys.argv) > 2:
    # We want to get the list of valuable crashes
    valuable_crashes = True
# Path to the directory containing your .<hash>.metadata files
directory_path = Path(__file__).parents[1] / "amd_sp" / "runs" / test_dir / "solutions"
if not valuable_crashes:
    print(f"Looking for metadata files in {directory_path}")

write_locations = defaultdict(lambda: defaultdict(set))
read_locations = defaultdict(lambda: defaultdict(set))

exceptions = defaultdict(lambda: defaultdict(set))

# Iterate over all files that match the .<hash>.metadata pattern
for file_path in directory_path.glob(".*.metadata"):
    try:
        with file_path.open("r") as f:
            name = file_path.name
            # Deduplicate the name for entries with the same hash
            first_hash = name.removeprefix(".").removesuffix(".metadata")
            first_hash = first_hash.split("-")[0]
            actual_data = directory_path / first_hash
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
                write_locations[write_pc][write_location].add(actual_data)
            if read_caught is not None:
                read_location, read_pc = read_caught
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
    except (json.JSONDecodeError, KeyError, IndexError, AttributeError) as e:
        print(
            f"Could not process {file_path}, possibly due to malformed JSON or unexpected structure. error: {e}"
        )
# python ./script/metadata_classifier.py tompute true > file_list.txt
# rsync -av -e ssh --files-from=file_list.txt amd_sp/runs/tompute/solutions tompute:~/projects/ASPFuzz/amd_sp/bins/seed
if valuable_crashes:
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
            f"PC: {hex(pc)}\t Write location: \t {hex(write_loc)}\t count: {len(entries)}\t Exemplar: {entries.pop()}"
        )

for pc, per_read_loc in read_locations.items():
    for read_loc, entries in per_read_loc.items():
        print(
            f"PC: {hex(pc)}\t Read location: \t {hex(read_loc)}\t count: {len(entries)}\t Exemplar: {entries.pop()}"
        )

for exception, per_lr in exceptions.items():
    for lr, entries in per_lr.items():
        print(
            f"Exception: \t {exception} \t LR: {lr}\t count: {len(entries)}\t Exemplar: {entries.pop()}"
        )

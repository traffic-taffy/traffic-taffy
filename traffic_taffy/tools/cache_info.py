"""Loads the cached data for a file to display the results about it."""

from argparse import ArgumentParser, Namespace
from rich_argparse import ArgumentDefaultsRichHelpFormatter
from pathlib import Path
from rich import print
import logging
import msgpack
from traffic_taffy import print_version


def parse_args() -> Namespace:
    """Parse the command line arguments."""
    parser = ArgumentParser(
        formatter_class=ArgumentDefaultsRichHelpFormatter,
        description=__doc__,
        epilog="Example Usage: taffy-cache-info something.taffy",
    )

    parser.add_argument(
        "--log-level",
        "--ll",
        default="info",
        help="Define the logging verbosity level (debug, info, warning, error, fotal, critical).",
    )

    parser.add_argument(
        "--version", action="store_true", help="print the Traffic-Taffy version number."
    )

    parser.add_argument(
        "cache_file",
        type=str,
        nargs="*",
        help="The cache file (or pcap file) to load and display information about",
    )

    args = parser.parse_args()
    log_level = args.log_level.upper()
    logging.basicConfig(level=log_level, format="%(levelname)-10s:\t%(message)s")
    if args.version:
        print_version()
    if len(args.cache_file) == 0:
        logging.error("Run without taffy cache files to analyze")
    return args


def main() -> None:
    """Run taffy-cache-info."""
    args = parse_args()

    for cache_file in args.cache_file:
        print(f"===== {cache_file} ======")
        with Path(cache_file).open("rb") as fh:
            contents = msgpack.load(fh, strict_map_key=False)

        # play the major keys
        for key in contents:
            if key != "dissection" and key != "parameters":
                print(f"{key:<20} {contents[key]}")

        # then the minors
        print("parameters:")
        for key in contents["parameters"]:
            print(f"    {key:<16} {contents['parameters'][key]}")

        print("data info:")
        timestamps = list(contents["dissection"].keys())
        print(f"    timestamps:      {len(timestamps)}")
        if len(timestamps) > 1:
            print(f"    first:           {timestamps[1]}")  # skips 0 = global
            print(f"    last:            {timestamps[-1]}")
        else:
            print("                     (only the entire summary timestamp)")


if __name__ == "__main__":
    main()

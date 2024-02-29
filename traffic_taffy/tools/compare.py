"""Takes a set of pcap files to compare and creates a report."""

import sys
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter, Namespace
import logging
from traffic_taffy.output.console import Console
from traffic_taffy.output.fsdb import Fsdb

from traffic_taffy.compare import compare_add_parseargs, get_comparison_args
from traffic_taffy.dissector import (
    dissector_add_parseargs,
    limitor_add_parseargs,
    check_dissector_level,
)
from traffic_taffy.compare import PcapCompare


def parse_args() -> Namespace:
    """Parse the command line arguments."""
    parser = ArgumentParser(
        formatter_class=ArgumentDefaultsHelpFormatter,
        description=__doc__,
        epilog="Example Usage: taffy-compare -C file1.pcap file2.pcap",
    )

    output_options = parser.add_argument_group("Output format")
    output_options.add_argument(
        "-f",
        "--fsdb",
        action="store_true",
        help="Print results in an FSDB formatted output",
    )

    limitor_parser = limitor_add_parseargs(parser)
    compare_add_parseargs(limitor_parser, add_subgroup=False)
    dissector_add_parseargs(parser)

    debugging_group = parser.add_argument_group("Debugging options")

    debugging_group.add_argument(
        "--log-level",
        "--ll",
        default="info",
        help="Define the logging verbosity level (debug, info, warning, error, ...).",
    )

    parser.add_argument("pcap_files", type=str, nargs="*", help="PCAP files to analyze")

    args = parser.parse_args()
    log_level = args.log_level.upper()
    logging.basicConfig(level=log_level, format="%(levelname)-10s:\t%(message)s")

    check_dissector_level(args.dissection_level)

    return args


def main() -> None:
    """Run taffy-compare."""
    args = parse_args()

    # setup output options
    printing_arguments = get_comparison_args(args)

    # get our files to compare (maybe just one)
    left = args.pcap_files.pop(0)
    right = None
    more_than_one = False

    if len(args.pcap_files) > 0:
        right = args.pcap_files.pop(0)
        more_than_one = True

    while left:
        files = [left]
        if right:
            files.append(right)

        pc = PcapCompare(
            files,
            cache_results=args.cache_pcap_results,
            cache_file_suffix=args.cache_file_suffix,
            maximum_count=printing_arguments["maximum_count"],
            dissection_level=args.dissection_level,
            # between_times=args.between_times,  # TODO(hardaker): TBD
            bin_size=args.bin_size,
            ignore_list=args.ignore_list,
            pcap_filter=args.filter,
            layers=args.layers,
            force_load=args.force_load,
            force_overwrite=args.force_overwrite,
            merge_files=args.merge,
        )

        # compare the pcaps
        try:
            reports = pc.compare()
        except ValueError:
            sys.exit()

        if args.fsdb:
            output = Fsdb(None, printing_arguments)
        else:
            output = Console(None, printing_arguments)

        for report in reports:
            # output results to the console
            output.output(report)

        left = right
        right = None
        if len(args.pcap_files) > 0:
            right = args.pcap_files.pop(0)

        if left and not right and more_than_one:
            left = None


if __name__ == "__main__":
    main()

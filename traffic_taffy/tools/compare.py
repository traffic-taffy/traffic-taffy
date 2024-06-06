"""Takes a set of pcap files to compare and creates a report."""

import sys
from argparse import ArgumentParser, Namespace
from rich_argparse import RichHelpFormatter
import logging
from logging import error
from traffic_taffy.output.console import Console
from traffic_taffy.output.fsdb import Fsdb
from traffic_taffy.config import Config

from traffic_taffy.compare import compare_add_parseargs, get_comparison_args
from traffic_taffy.dissector import (
    dissector_add_parseargs,
    limitor_add_parseargs,
    dissector_handle_arguments,
)
from traffic_taffy.compare import PcapCompare


def parse_args() -> Namespace:
    """Parse the command line arguments."""

    config: Config = Config()
    config.config_option_names = ["-y", "--config"]
    config["log_level"] = "info"

    config.read_configfile_from_arguments(sys.argv)

    parser = ArgumentParser(
        formatter_class=RichHelpFormatter,
        description=__doc__,
        epilog="Example Usage: taffy-compare -C file1.pcap file2.pcap",
    )

    parser.add_argument(
        "-y",
        "--config",
        default=None,
        type=str,
        help="Configuration file (YAML) to load.",
    )

    output_options = parser.add_argument_group("Output format")
    output_options.add_argument(
        "-f",
        "--fsdb",
        action="store_true",
        help="Print results in an FSDB formatted output",
    )

    limitor_parser = limitor_add_parseargs(parser, config)
    compare_add_parseargs(limitor_parser, config, add_subgroup=False)
    dissector_add_parseargs(parser, config)

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

    dissector_handle_arguments(args)

    config.load_namespace(args)
    return config


def main() -> None:
    """Run taffy-compare."""
    config = parse_args()
    args = config.as_namespace()

    # setup output options
    config["filter_arguments"] = get_comparison_args(args)

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
            config,
        )

        # compare the pcaps
        try:
            reports = pc.compare()
        except ValueError as e:
            error(e)
            sys.exit()

        if args.fsdb:
            output = Fsdb(None, config["filter_arguments"])
        else:
            output = Console(None, config["filter_arguments"])

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

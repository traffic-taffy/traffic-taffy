"""Takes a set of pcap files to compare and creates a report."""

import sys
from argparse import Namespace
from argparse_with_config import ArgumentParserWithConfig
from rich_argparse import RichHelpFormatter
import logging
from logging import error
from traffic_taffy.output.console import Console
from traffic_taffy.output.fsdb import Fsdb
from traffic_taffy.taffy_config import TaffyConfig, taffy_default

from traffic_taffy.compare import compare_add_parseargs, get_comparison_args
from traffic_taffy.dissector import (
    dissector_add_parseargs,
    limitor_add_parseargs,
    dissector_handle_arguments,
    TTD_CFG,
)
from traffic_taffy.compare import PcapCompare

taffy_default("compare.fsdb", False)


def compare_parse_args() -> Namespace:
    """Parse the command line arguments."""

    config: TaffyConfig = TaffyConfig()

    parser = ArgumentParserWithConfig(
        formatter_class=RichHelpFormatter,
        description=__doc__,
        epilog="Example Usage: taffy-compare -C file1.pcap file2.pcap",
        default_config=config,
    )

    output_options = parser.add_argument_group("Output format")
    output_options.add_argument(
        "-f",
        "--fsdb",
        action="store_true",
        config_path="compare.output_fsdb",
        help="Print results in an FSDB formatted output",
    )

    limitor_add_parseargs(parser, config)
    compare_add_parseargs(parser, config)
    dissector_add_parseargs(parser, config)

    debugging_group = parser.add_argument_group("Debugging options")

    debugging_group.add_argument(
        "--log-level",
        "--ll",
        default="info",
        config_path="log_level",
        help="Define the logging verbosity level (debug, info, warning, error, ...).",
    )

    parser.add_argument("pcap_files", type=str, nargs="*", help="PCAP files to analyze")

    args = parser.parse_args()
    log_level = args.log_level.upper()
    logging.basicConfig(level=log_level, format="%(levelname)-10s:\t%(message)s")

    dissector_handle_arguments(args)

    return parser.config, args


def main() -> None:
    """Run taffy-compare."""
    config, args = compare_parse_args()

    # setup output options
    config[TTD_CFG.KEY_DISSECTOR][TTD_CFG.FILTER_ARGUMENTS] = get_comparison_args(
        config
    )

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
            output = Fsdb(None, config[TTD_CFG.KEY_DISSECTOR][TTD_CFG.FILTER_ARGUMENTS])
        else:
            output = Console(
                None, config[TTD_CFG.KEY_DISSECTOR][TTD_CFG.FILTER_ARGUMENTS]
            )

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
    config = TaffyConfig()
    if config.get("dump", False):
        config.dump()

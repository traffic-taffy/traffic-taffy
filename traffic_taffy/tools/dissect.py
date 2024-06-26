"""Performs generic dissection of a PCAP file."""
import sys
import logging
from logging import error
from traffic_taffy.dissector import (
    dissector_add_parseargs,
    limitor_add_parseargs,
    dissector_handle_arguments,
    PCAPDissector,
)
from traffic_taffy.dissectmany import PCAPDissectMany
from traffic_taffy.taffy_config import TaffyConfig, TT_CFG
from rich_argparse import RichHelpFormatter
from argparse import Namespace
from argparse_with_config import ArgumentParserWithConfig


def dissect_parse_args() -> Namespace:
    """Parse the command line arguments."""

    config: TaffyConfig = TaffyConfig()
    config[TT_CFG.LOG_LEVEL] = "info"

    parser = ArgumentParserWithConfig(
        formatter_class=RichHelpFormatter,
        description=__doc__,
        epilog="Example Usage: taffy-dissect -C -d 10 -n 10000 file.pcap",
        default_config=config,
    )

    parser.add_argument(
        "--log-level",
        "--ll",
        default="info",
        config_path="log_level",
        help="Define the logging verbosity level (debug, info, warning, error, fotal, critical).",
    )

    parser.add_argument(
        "-f",
        "--fsdb",
        action="store_true",
        help="Print results in an FSDB formatted output",
    )

    parser.add_argument(
        "--dont-fork",
        action="store_true",
        config_path="dissect.dont_fork",
        help="Do not fork into multiple processes per file (still fork per file)",
    )

    dissector_add_parseargs(parser, config)
    limitor_add_parseargs(parser, config)

    parser.add_argument("input_pcaps", type=str, help="input pcap file", nargs="*")

    args = parser.parse_args()
    log_level = args.log_level.upper()
    logging.basicConfig(level=log_level, format="%(levelname)-10s:\t%(message)s")

    return (parser.config, args)


def main() -> None:
    """Dissect a pcap file and report contents."""

    config, args = dissect_parse_args()

    dissector_handle_arguments(args)

    # load all the files
    pdm = PCAPDissectMany(
        args.input_pcaps,
        config,
    )
    try:
        dissections = pdm.load_all(return_as_list=True, dont_fork=args.dont_fork)
    except ValueError as e:
        error(e)
        sys.exit()

    # merge them into a single dissection
    dissection = dissections.pop(0)
    dissection.merge_all(dissections)

    # put the dissection into a dissector for reporting
    pd = PCAPDissector(args.input_pcaps, config)
    pd.dissection = dissection

    # output as requested
    if args.fsdb:
        pd.print_to_fsdb(
            timestamps=[0],
            match_string=args.match_string,
            match_value=args.match_value,
            minimum_count=args.minimum_count,
            match_expression=args.match_expression,
        )
    else:
        pd.print(
            timestamps=[0],
            match_string=args.match_string,
            match_value=args.match_value,
            minimum_count=args.minimum_count,
            match_expression=args.match_expression,
        )


if __name__ == "__main__":
    main()

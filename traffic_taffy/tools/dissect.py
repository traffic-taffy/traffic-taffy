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
from traffic_taffy.config import Config
from rich_argparse import RichHelpFormatter
from argparse import ArgumentParser, Namespace


def main() -> None:
    """Dissect a pcap file and report contents."""

    def parse_args() -> Namespace:
        """Parse the command line arguments."""

        config: Config = Config()
        config.config_option_names = ["-y", "--config"]
        config["log_veles"] = "info"

        config.read_configfile_from_arguments(sys.argv)

        parser = ArgumentParser(
            formatter_class=RichHelpFormatter,
            description=__doc__,
            epilog="Example Usage: taffy-dissect -C -d 10 -n 10000 file.pcap",
        )

        parser.add_argument(
            "-y",
            "--config",
            default=None,
            type=str,
            help="Configuration file (YAML) to load.",
        )

        parser.add_argument(
            "--log-level",
            "--ll",
            default="info",
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
            help="Do not fork into multiple processes per file (still fork per file)",
        )

        dissector_add_parseargs(parser, config)
        limitor_add_parseargs(parser, config)

        parser.add_argument("input_pcaps", type=str, help="input pcap file", nargs="*")

        args = parser.parse_args()
        log_level = args.log_level.upper()
        logging.basicConfig(level=log_level, format="%(levelname)-10s:\t%(message)s")

        config.load_namespace(args)
        return config

    config = parse_args()
    args = config.as_namespace()

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

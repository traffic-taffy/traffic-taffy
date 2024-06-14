"""Export the results of a traffic-taffy dissection(s) into an FSDB file."""

import logging
import sys
from argparse import ArgumentParser, FileType, Namespace
from rich_argparse import RichHelpFormatter

import pyfsdb

from traffic_taffy.taffy_config import TaffyConfig, TT_CFG
from traffic_taffy.dissectmany import PCAPDissectMany
from traffic_taffy.dissector import (
    dissector_add_parseargs,
    limitor_add_parseargs,
    dissector_handle_arguments,
)


def parse_args() -> Namespace:
    """Parse the command line arguments for taffy-export."""

    config: TaffyConfig = TaffyConfig()
    config.config_option_names = ["-y", "--config"]
    config[TT_CFG.LOG_LEVEL] = "info"

    config.read_configfile_from_arguments(sys.argv)

    parser = ArgumentParser(
        formatter_class=RichHelpFormatter,
        description=__doc__,
        epilog="Example Usage: taffy-export -C -m IP.UDP.sport file.pcap",
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

    dissector_add_parseargs(parser, config)
    limitor_add_parseargs(parser, config)

    parser.add_argument(
        "-o",
        "--output-file",
        default=sys.stdout,
        type=FileType("w"),
        help="Where to store output data",
    )

    parser.add_argument("input_pcaps", nargs="*", type=str, help="input pcap file")

    args = parser.parse_args()
    log_level = args.log_level.upper()
    logging.basicConfig(level=log_level, format="%(levelname)-10s:\t%(message)s")

    config.load_namespace(args)
    return config


def main() -> None:
    """Export traffic-taffy data into an FSDB file."""
    config = parse_args()
    args = config.as_namespace()

    dissector_handle_arguments(args)

    del config["output_file"]  # this causes a msgpack problem
    pdm = PCAPDissectMany(
        args.input_pcaps,
        config,
    )

    dissections = pdm.load_all(return_as_list=True)
    dissection = dissections.pop()
    dissection.merge_all(dissections)

    # TODO(hardaker): make this optional
    del dissection.data[0]  # delete the summary timestamp

    oh = pyfsdb.Fsdb(out_file_handle=args.output_file)
    oh.out_column_names = ["timestamp", "key", "value", "count"]
    oh.converters = {"timestamp": int, "count": int}
    for timestamp, key, subkey, count in dissection.find_data(
        match_string=args.match_string,
        match_value=args.match_value,
        minimum_count=args.minimum_count,
        make_printable=True,
    ):
        oh.append([timestamp, key, subkey, count])


if __name__ == "__main__":
    main()

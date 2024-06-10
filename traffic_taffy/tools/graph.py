"""Read a PCAP file and graph it or parts of it."""

import sys
import logging
from argparse import ArgumentParser, Namespace
from rich_argparse import RichHelpFormatter

from traffic_taffy.graph import PcapGraph
from traffic_taffy.taffy_config import TaffyConfig
from traffic_taffy.dissector import (
    dissector_add_parseargs,
    limitor_add_parseargs,
    dissector_handle_arguments,
)


def parse_args() -> Namespace:
    """Parse the command line arguments."""

    config: TaffyConfig = TaffyConfig()
    config.config_option_names = ["-y", "--config"]
    config["log_level"] = "info"
    config["output_file"] = None
    config["by_percentage"] = False
    config["interactive"] = False

    config.read_configfile_from_arguments(sys.argv)

    parser = ArgumentParser(
        formatter_class=RichHelpFormatter,
        description=__doc__,
        epilog="Example Usage: taffy-graph -C -m __TOTAL__ -M packet -o graph.png file.pcap",
    )

    parser.add_argument(
        "-o",
        "--output-file",
        default=None,
        type=str,
        help="Where to save the output (png)",
    )

    parser.add_argument(
        "-p",
        "--by-percentage",
        action="store_true",
        help="Graph by percentage of traffic rather than by value",
    )

    parser.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="Prompt repeatedly for graph data to create",
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
        help="Define verbosity level (debug, info, warning, error, fotal, critical).",
    )

    dissector_add_parseargs(parser, config)
    limitor_add_parseargs(parser, config)

    parser.add_argument("input_pcaps", type=str, help="PCAP file to graph", nargs="+")

    args = parser.parse_args()
    log_level = args.log_level.upper()
    logging.basicConfig(level=log_level, format="%(levelname)-10s:\t%(message)s")
    logging.getLogger("matplotlib.font_manager").setLevel(logging.ERROR)

    dissector_handle_arguments(args)
    config.load_namespace(args)

    return config


def main() -> None:
    """Run taffy-graph."""
    config = parse_args()
    args = config.as_namespace()

    pc = PcapGraph(
        args.input_pcaps,
        args.output_file,
        config,
    )
    pc.graph_it()


if __name__ == "__main__":
    main()

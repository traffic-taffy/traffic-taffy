"""Read a PCAP file and graph it or parts of it."""

import logging
from argparse import Namespace
from argparse_with_config import ArgumentParserWithConfig
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

    parser = ArgumentParserWithConfig(
        formatter_class=RichHelpFormatter,
        description=__doc__,
        epilog="Example Usage: taffy-graph -C -m __TOTAL__ -M packet -o graph.png file.pcap",
        default_config=config,
    )

    parser.add_argument(
        "-o",
        "--output-file",
        default=None,
        config_path="graph.output_file",
        type=str,
        help="Where to save the output (png)",
    )

    parser.add_argument(
        "-p",
        "--by-percentage",
        config_path="graph.by_percentage",
        action="store_true",
        help="Graph by percentage of traffic rather than by value",
    )

    parser.add_argument(
        "-i",
        "--interactive",
        config_path="graph.interactive",
        action="store_true",
        help="Prompt repeatedly for graph data to create",
    )

    parser.add_argument(
        "--log-level",
        "--ll",
        default="info",
        config_path="log_level",
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

    return parser.config, args


def main() -> None:
    """Run taffy-graph."""
    config, args = parse_args()

    pc = PcapGraph(
        args.input_pcaps,
        args.output_file,
        config,
    )
    pc.graph_it()


if __name__ == "__main__":
    main()

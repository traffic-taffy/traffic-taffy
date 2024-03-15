"""Read a PCAP file and graph it or parts of it."""

from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter, Namespace
from traffic_taffy.graph import PcapGraph
from traffic_taffy.dissector import (
    dissector_add_parseargs,
    limitor_add_parseargs,
    dissector_handle_arguments,
)
import logging


def parse_args() -> Namespace:
    """Parse the command line arguments."""
    parser = ArgumentParser(
        formatter_class=ArgumentDefaultsHelpFormatter,
        description=__doc__,
        epilog="Example Usage: taffy-graph -C -m TOTAL -M packet -o graph.png file.pcap",
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
        "--log-level",
        "--ll",
        default="info",
        help="Define verbosity level (debug, info, warning, error, fotal, critical).",
    )

    dissector_add_parseargs(parser)
    limitor_add_parseargs(parser)

    parser.add_argument("input_pcaps", type=str, help="PCAP file to graph", nargs="+")

    args = parser.parse_args()
    log_level = args.log_level.upper()
    logging.basicConfig(level=log_level, format="%(levelname)-10s:\t%(message)s")
    logging.getLogger("matplotlib.font_manager").setLevel(logging.ERROR)
    return args


def main() -> None:
    """Run taffy-graph."""
    args = parse_args()

    dissector_handle_arguments(args)

    pc = PcapGraph(
        args.input_pcaps,
        args.output_file,
        maximum_count=args.packet_count,
        minimum_count=args.minimum_count,
        bin_size=args.bin_size,
        match_string=args.match_string,
        match_value=args.match_value,
        cache_pcap_results=args.cache_pcap_results,
        dissector_level=args.dissection_level,
        interactive=args.interactive,
        by_percentage=args.by_percentage,
        ignore_list=args.ignore_list,
        pcap_filter=args.filter,
        cache_file_suffix=args.cache_file_suffix,
        layers=args.layers,
        force_overwrite=args.force_overwrite,
        force_load=args.force_load,
        merge_files=args.merge,
    )
    pc.graph_it()


if __name__ == "__main__":
    main()

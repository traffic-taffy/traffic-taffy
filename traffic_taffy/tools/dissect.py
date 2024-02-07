"""Performs generic dissection of a PCAP file."""
import logging
from traffic_taffy.dissector import (
    dissector_add_parseargs,
    limitor_add_parseargs,
    check_dissector_level,
    PCAPDissector,
)
from traffic_taffy.dissectmany import PCAPDissectMany
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter, Namespace


def main() -> None:
    """Dissect a pcap file and report contents."""

    def parse_args() -> Namespace:
        """Parse the command line arguments."""
        parser = ArgumentParser(
            formatter_class=ArgumentDefaultsHelpFormatter,
            description=__doc__,
            epilog="Example Usage: taffy-dissect -C -d 10 -n 10000 file.pcap",
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

        dissector_add_parseargs(parser)
        limitor_add_parseargs(parser)

        parser.add_argument("input_pcaps", type=str, help="input pcap file", nargs="*")

        args = parser.parse_args()
        log_level = args.log_level.upper()
        logging.basicConfig(level=log_level, format="%(levelname)-10s:\t%(message)s")
        return args

    args = parse_args()

    check_dissector_level(args.dissection_level)

    # load all the files
    pdm = PCAPDissectMany(
        args.input_pcaps,
        bin_size=args.bin_size,
        dissector_level=args.dissection_level,
        maximum_count=args.packet_count,
        cache_results=args.cache_pcap_results,
        cache_file_suffix=args.cache_file_suffix,
        ignore_list=args.ignore_list,
        pcap_filter=args.filter,
        layers=args.layers,
        force_overwrite=args.force_overwrite,
        force_load=args.force_load,
    )
    dissections = pdm.load_all(return_as_list=True, dont_fork=args.dont_fork)

    # merge them into a single dissection
    dissection = dissections.pop(0)
    dissection.merge_all(dissections)

    # put the dissection into a dissector for reporting
    pd = PCAPDissector(
        args.input_pcaps[0],
        bin_size=args.bin_size,
        dissector_level=args.dissection_level,
        maximum_count=args.packet_count,
        cache_results=args.cache_pcap_results,
        cache_file_suffix=args.cache_file_suffix,
        ignore_list=args.ignore_list,
        pcap_filter=args.filter,
        layers=args.layers,
        force_overwrite=args.force_overwrite,
        force_load=args.force_load,
    )
    pd.dissection = dissection

    # output as requested
    if args.fsdb:
        pd.print_to_fsdb(
            timestamps=[0],
            match_string=args.match_string,
            match_value=args.match_value,
            minimum_count=args.minimum_count,
        )
    else:
        pd.print(
            timestamps=[0],
            match_string=args.match_string,
            match_value=args.match_value,
            minimum_count=args.minimum_count,
        )


if __name__ == "__main__":
    main()

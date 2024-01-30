from traffic_taffy.dissector import (
    dissector_add_parseargs,
    limitor_add_parseargs,
    check_dissector_level,
    PCAPDissector,
)
from traffic_taffy.dissectmany import PCAPDissectMany


def main():
    from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
    import logging

    def parse_args():
        "Parse the command line arguments."
        parser = ArgumentParser(
            formatter_class=ArgumentDefaultsHelpFormatter,
            description=__doc__,
            epilog="Exmaple Usage: ",
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

        dissector_add_parseargs(parser)
        limitor_add_parseargs(parser)

        parser.add_argument("input_file", type=str, help="input pcap file")

        args = parser.parse_args()
        log_level = args.log_level.upper()
        logging.basicConfig(level=log_level, format="%(levelname)-10s:\t%(message)s")
        return args

    args = parse_args()

    check_dissector_level(args.dissection_level)

    pdm = PCAPDissectMany(
        args.input_file,
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
    dissection = pdm.load_pcap(
        args.input_file,
        maximum_count=args.packet_count,
        force_overwrite=args.force_overwrite,
        force_load=args.force_load,
    )
    pd = PCAPDissector(
        args.input_file,
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

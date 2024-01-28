import sys
import pyfsdb
from traffic_taffy.dissector import (
    dissector_add_parseargs,
    limitor_add_parseargs,
    check_dissector_level,
)
from traffic_taffy.dissectmany import PCAPDissectMany


def main():
    from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter, FileType
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

        parser.add_argument(
            "-o",
            "--output-file",
            default=sys.stdout,
            type=FileType("w"),
            help="Where to store output data",
        )

        parser.add_argument("input_files", nargs="*", type=str, help="input pcap file")

        args = parser.parse_args()
        log_level = args.log_level.upper()
        logging.basicConfig(level=log_level, format="%(levelname)-10s:\t%(message)s")
        return args

    args = parse_args()

    check_dissector_level(args.dissection_level)

    pdm = PCAPDissectMany(
        args.input_files,
        bin_size=args.bin_size,
        dissector_level=args.dissection_level,
        maximum_count=args.packet_count,
        cache_results=args.cache_pcap_results,
        cache_file_suffix=args.cache_file_suffix,
        ignore_list=args.ignore_list,
        pcap_filter=args.filter,
        layers=args.layers,
    )

    dissections = pdm.load_all(return_as_list=True)
    dissection = dissections.pop()
    dissection.merge_all(dissections)

    # TODO: make this optional
    del dissection[0]  # delete the summary timestamp

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

"""Takes a set of pcap files to compare and dumps a report"""

from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
import logging

from pcap_compare import PcapCompare

def parse_args():
    "Parse the command line arguments."
    parser = ArgumentParser(
        formatter_class=ArgumentDefaultsHelpFormatter,
        description=__doc__,
        epilog="Exmaple Usage: ",
    )

    parser.add_argument(
        "-n",
        "--packet-count",
        default=-1,
        type=int,
        help="Maximum number of packets to analyze",
    )

    parser.add_argument(
        "-t",
        "--print-threshold",
        default=None,
        type=float,
        help="Don't print results with abs(value) less than threshold",
    )

    parser.add_argument(
        "-m",
        "--print-match-string",
        default=None,
        type=str,
        help="Only report on data with this substring in the header",
    )

    parser.add_argument(
        "-s",
        "--save-report",
        default=None,
        type=str,
        help="Where to save a report file for quicker future loading",
    )

    parser.add_argument(
        "-l",
        "--load-report",
        default=None,
        type=str,
        help="Load a report from a pickle file rather than use pcaps",
    )

    parser.add_argument(
        "-c",
        "--print-minimum-count",
        default=None,
        type=float,
        help="Don't print results without this high of a count",
    )

    parser.add_argument(
        "-P", "--only-positive", action="store_true", help="Only show positive entries"
    )

    parser.add_argument(
        "-N", "--only-negative", action="store_true", help="Only show negative entries"
    )

    parser.add_argument(
        "--log-level",
        "--ll",
        default="info",
        help="Define the logging verbosity level (debug, info, warning, error, ...).",
    )

    parser.add_argument("pcap_files", type=str, nargs="*", help="PCAP files to analyze")

    args = parser.parse_args()
    log_level = args.log_level.upper()
    logging.basicConfig(level=log_level, format="%(levelname)-10s:\t%(message)s")
    return args


def main():
    args = parse_args()
    pc = PcapCompare(
        args.pcap_files,
        maximum_count=args.packet_count,
        print_threshold=args.print_threshold,
        print_minimum_count=args.print_minimum_count,
        print_match_string=args.print_match_string,
        only_positive=args.only_positive,
        only_negative=args.only_negative,
    )

    # TODO: throw an error when both pcaps and load files are specified

    if args.load_report:
        # load a previous saved dump
        pc.load_report(args.load_report)
    else:
        # actually compare the pcaps
        pc.compare()

    # print the results
    pc.print()

    # maybe save them
    # TODO: loading and saving both makes more sense, throw error
    if args.save_report:
        pc.save_report(args.save_report)


if __name__ == "__main__":
    main()

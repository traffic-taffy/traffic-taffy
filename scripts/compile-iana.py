#!/usr/bin/python

"""Loads IANA tables into a dictionary and saves them in a giant pickle dict"""

from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from logging import debug
from pathlib import Path
from collections import defaultdict
import logging
import xmltodict
import pickle

# optionally use rich
try:
    from rich.logging import RichHandler
except Exception:
    pass


def parse_args():
    "Parse the command line arguments."
    parser = ArgumentParser(
        formatter_class=ArgumentDefaultsHelpFormatter,
        description=__doc__,
        epilog="Example Usage: ",
    )

    parser.add_argument(
        "-d",
        "--base-dir",
        default="../iana-registries",
        type=str,
        help="The top of the rsynced iana registration dataset.",
    )

    parser.add_argument(
        "--log-level",
        "--ll",
        default="info",
        help="Define the logging verbosity level (debug, info, warning, error, fotal, critical).",
    )

    parser.add_argument(
        "output_file",
        type=str,
        nargs="?",
        default="traffic_taffy/data/iana_tables.pkl",
        help="Where to store the pickled data tables",
    )

    args = parser.parse_args()
    log_level = args.log_level.upper()
    handlers = []
    datefmt = None
    messagefmt = "%(levelname)-10s:\t%(message)s"

    # see if we're rich
    try:
        handlers.append(RichHandler(rich_tracebacks=True))
        datefmt = " "
        messagefmt = "%(message)s"
    except Exception:
        pass

    logging.basicConfig(
        level=log_level, format=messagefmt, datefmt=datefmt, handlers=handlers
    )
    return args


def get_data(base_dir: Path, identifier: str) -> dict:
    """Loads data from a xml file and returns the near-top"""
    root = Path("/home/hardaker/docs/iana-registries/")
    algs = root.joinpath(f"{identifier}/{identifier}.xml")
    data = xmltodict.parse(open(algs).read())
    top = data["registry"]

    return top


def main():
    args = parse_args()

    base = Path(args.base_dir)

    # load port numbers
    data = get_data(base, "service-names-port-numbers")
    records = data["record"]
    port_data = defaultdict(dict)
    for record in records:
        if "name" in record and "protocol" in record and "number" in record:
            port_data[record["protocol"]][record["number"]] = record["name"]
        else:
            debug(record)
    for port_type in port_data:
        data[port_type + "_ports"] = port_data[port_type]

    with open(args.output_file, "wb") as output_h:
        pickle.dump(data, output_h)


if __name__ == "__main__":
    main()

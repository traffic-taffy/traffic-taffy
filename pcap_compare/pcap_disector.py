"""Loads a PCAP file and counts contents with various levels of storage"""

from enum import Enum
from logging import warning
from collections import Counter, defaultdict


class PCAPDisectorType(Enum):
    DETAILED = 1
    COUNT_ONLY = 2


class PCAPDisector:
    "loads a pcap file and counts the contents in both time and depth"
    TOTAL_COUNT: str = "__TOTAL__"

    def __init__(
        self,
        pcap_file: str,
        bin_size: int = 0,
        maximum_count: int = 0,
        disector_type: PCAPDisectorType = PCAPDisectorType.DETAILED,
        pcap_filter: str | None = None,
    ):
        self.pcap_file = pcap_file
        self.bin_size = bin_size
        self.disector_type = disector_type
        self.pcap_filter = pcap_filter
        self.maximum_count = maximum_count

        if disector_type == PCAPDisectorType.COUNT_ONLY and bin_size == 0:
            warning("counting packets only with no binning is unlikely to be helpful")

    @property
    def data(self):
        return self.__data

    @data.setter
    def data(self, value):
        self.__data = value

    def load(self) -> dict:
        if self.disector_type == PCAPDisectorType.COUNT_ONLY:
            return self.load_via_dpkt()
        else:
            return self.load_via_scapy()

    def dpkt_callback(self, timestamp: float, packet: bytes):
        time_stamp = int(timestamp)

        # if binning is requested, save it in a binned time slot
        if self.bin_size:
            time_stamp = time_stamp - time_stamp % self.bin_size
            self.data[time_stamp][self.TOTAL_COUNT] += 1

        # always save a total count at the zero bin
        # note: there should be no recorded tcpdump files from 1970 Jan 01 :-)
        self.data[0][self.TOTAL_COUNT] += 1

    def load_via_dpkt(self) -> dict:
        import dpkt

        self.data = defaultdict(Counter)
        pcap = dpkt.pcap.Reader(open(self.pcap_file, "rb"))
        if self.pcap_filter:
            pcap.setfilter(self.pcap_filter)
        pcap.dispatch(self.maximum_count, self.dpkt_callback)


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

        parser.add_argument("input_file", type=str, help="input pcap file")

        args = parser.parse_args()
        log_level = args.log_level.upper()
        logging.basicConfig(level=log_level, format="%(levelname)-10s:\t%(message)s")
        return args

    args = parse_args()
    pd = PCAPDisector(
        args.input_file,
        bin_size=1,
        disector_type=PCAPDisectorType.COUNT_ONLY,
        maximum_count=1000,
    )
    pd.load()
    import rich

    rich.print(pd.data)


if __name__ == "__main__":
    main()

"""Loads a PCAP file and counts contents with various levels of storage"""

from enum import Enum
from logging import warning, debug
from collections import Counter, defaultdict
from scapy.all import rdpcap

class PCAPDisectorType(Enum):
    DETAILED = 1
    COUNT_ONLY = 2


class PCAPDisector:
    "loads a pcap file and counts the contents in both time and depth"
    TOTAL_COUNT: str = "__TOTAL__"
    TOTAL_SUBKEY: str = "packet"

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
        # TODO: convert to a factory
        self.data = {0: defaultdict(Counter)}

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
            if time_stamp not in self.data:
                self.data[time_stamp] = defaultdict(Counter)
            self.data[time_stamp][self.TOTAL_COUNT][self.TOTAL_SUBKEY] += 1

        # always save a total count at the zero bin
        # note: there should be no recorded tcpdump files from 1970 Jan 01 :-)
        self.data[0][self.TOTAL_COUNT][self.TOTAL_SUBKEY] += 1

    def load_via_dpkt(self) -> dict:
        import dpkt

        self.data = defaultdict(Counter)
        pcap = dpkt.pcap.Reader(open(self.pcap_file, "rb"))
        if self.pcap_filter:
            pcap.setfilter(self.pcap_filter)
        pcap.dispatch(self.maximum_count, self.dpkt_callback)
        return self.data

    def add_scapy_item(self, field_value, prefix: str) -> None:
        "Adds an item to the self.data regardless of it's various types"
        if isinstance(field_value, list):
            if len(field_value) > 0:
                # if it's a list of tuples, count the (eg TCP option) names
                # TODO: values can be always the same or things like timestamps
                #       that will always change or are too unique
                if isinstance(field_value[0], tuple):
                    for item in field_value:
                        self.data[prefix][item[0]] += 1
                else:
                    for item in field_value:
                        self.add_scapy_item(item, prefix)
            else:
                debug(f"ignoring empty-list: {field_value}")
        elif (
            isinstance(field_value, str)
            or isinstance(field_value, int)
            or isinstance(field_value, float)
        ):
            self.data[prefix][field_value] += 1

        elif isinstance(field_value, bytes):
            try:
                converted = field_value.decode("utf-8")
                self.data[prefix][converted] += 1
            except Exception:
                converted = "0x" + field_value.hex()
                self.data[prefix][converted] += 1

    def add_scapy_layer(self, layer, prefix: str | None = "") -> None:
        "Analyzes a layer to add counts to each layer sub-component"

        if hasattr(layer, "fields_desc"):
            name_list = [field.name for field in layer.fields_desc]
        elif hasattr(layer, "fields"):
            name_list = [field.name for field in layer.fields]
        else:
            warning(f"unavailable to deep dive into: {layer}")
            return

        for field_name in name_list:
            field_value = getattr(layer, field_name)
            if hasattr(field_value, "fields"):
                self.add_scapy_layer(field_value, prefix + field_name + ".")
            else:
                self.add_scapy_item(field_value, prefix + field_name)

    def load_via_scapy(self) -> dict:
        "Loads a pcap file into a nested dictionary of statistical counts"
        results = defaultdict(Counter)
        packets = rdpcap(self.pcap_file, count=self.maximum_count)

        for packet in packets:
            prefix = "."
            for payload in packet.iterpayloads():
                prefix = f"{prefix}{payload.name}."
                self.add_scapy_layer(payload, prefix[1:])

        return results

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
            "-b", "--bin-size", default=1, type=int, help="bin size to use"
        )

        parser.add_argument("-f", "--full-dump", action="store_true",
                            help="Full deep-inspect the packet")

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
    disect_type = PCAPDisectorType.COUNT_ONLY
    if args.full_dump:
        disect_type = PCAPDisectorType.DETAILED
    pd = PCAPDisector(
        args.input_file,
        bin_size=args.bin_size,
        disector_type=disect_type,
        maximum_count=1000,
    )
    pd.load()
    import rich

    rich.print(pd.data)


if __name__ == "__main__":
    main()

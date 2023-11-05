"""Loads a PCAP file and counts contents with various levels of storage"""

import io
from typing import List
import dpkt
from rich import print


class PCAPSplitter:
    "Quickly reads a PCAP file and splits into multiple io.BytesIO streams"

    def __init__(
        self,
        pcap_file: str,
        callback=None,
        split_size: int = 0,
        maximum_count: int = 0,
        pcap_filter: str | None = None,
    ) -> List[io.BytesIO]:
        self.pcap_file: str = pcap_file
        self.callback = callback
        self.split_size: int = split_size
        self.maximum_count: int = maximum_count
        self.pcap_filter: str | None = pcap_filter

        self.header: bytes = None
        self.buffer: bytes = None
        self.packets_read: int = 0
        self.dpkt_data = None
        self.our_data = None
        self.results: List[io.BytesIO] = []

    def split(self):
        "Does the actual reading and splitting"
        # open one for the dpkt reader and one for us independently
        self.our_data = open(self.pcap_file, "rb")
        self.dpkt_data = open(self.pcap_file, "rb")

        # read the first 24 bytes which is the pcap header
        self.header = self.our_data.read(24)

        # now process with dpkt to pull out each packet
        pcap = dpkt.pcap.Reader(self.dpkt_data)
        if self.pcap_filter:
            pcap.setfilter(self.pcap_filter)
        pcap.dispatch(self.maximum_count, self.dpkt_callback)

        # TODO: need to process the remaining bytes
        self.save_packets()

        print(f"total packets read: {self.packets_read}")
        return self.results

    def save_packets(self):
        "Saves the contents seen to this point into a new io.BytesIO"
        self.buffer = bytes(self.header)

        # read from our files current position to where the dpkt reader is
        bytes_to_read: int = self.dpkt_data.tell() - self.our_data.tell()
        self.buffer += self.our_data.read(bytes_to_read)

        print(f"buffer size = {len(self.buffer)}")
        self.results.append(io.BytesIO(self.buffer))

        # if we've collected data, call the callback
        # TODO: multi-processer needed here

    def dpkt_callback(self, timestamp: float, packet: bytes):
        "Handles each packet received by dpkt"
        self.packets_read += 1

        if self.packets_read % self.split_size == 0:
            print(f"here: {self.packets_read}")
            self.save_packets()


def main():
    ps = PCAPSplitter("test.pcap", split_size=10, maximum_count=200)
    buffers = ps.split()
    print(buffers)

    def test_dpkt_callback(timestamp, packet):
        print(f"{timestamp} {len(packet)}")

    for n, buffer in enumerate(buffers):
        print(f"---- {n}")
        pcap = dpkt.pcap.Reader(buffer)
        e = pcap.dispatch(0, test_dpkt_callback)
        print(f"   = {e}")


if __name__ == "__main__":
    main()

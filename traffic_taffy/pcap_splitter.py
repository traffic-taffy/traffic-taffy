"""Loads a PCAP file and counts contents with various levels of storage"""

import io
from typing import List
import dpkt
import time
from rich import print
from concurrent.futures import ProcessPoolExecutor
from dissector import PCAPDissector, pcap_data_merge


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
        self.process_pool = ProcessPoolExecutor()

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

        import time

        time.sleep(1)
        for p in self.results:
            print(f"Running: {p.running()}")

        for p in self.results:
            print(f"now waiting: {p.result()}")

        self.process_pool.shutdown(wait=True, cancel_futures=False)

        print(f"total packets read: {self.packets_read}")
        return self.results

    def save_packets(self):
        "Saves the contents seen to this point into a new io.BytesIO"
        self.buffer = bytes(self.header)

        # read from our files current position to where the dpkt reader is
        bytes_to_read: int = self.dpkt_data.tell() - self.our_data.tell()
        self.buffer += self.our_data.read(bytes_to_read)

        print(f"buffer size = {len(self.buffer)}")

        if self.callback:
            self.results.append(
                self.process_pool.submit(self.callback, io.BytesIO(self.buffer))
            )
        #            self.results[-1].result(timeout=0.001)  # force a start
        # print(f"running: {self.results[-1].running()}")
        # print(f"done: {self.results[-1].done()}")
        else:
            self.results.append(io.BytesIO(self.buffer))

        # if we've collected data, call the callback
        # TODO: multi-processer needed here

    def dpkt_callback(self, timestamp: float, packet: bytes):
        "Handles each packet received by dpkt"
        self.packets_read += 1

        if self.packets_read % self.split_size == 0:
            self.save_packets()


def buffer_callback(pcap_io_buffer):
    pd = PCAPDissector(
        pcap_io_buffer,
        bin_size=0,
        dissector_level=10,
        cache_results=False,
    )
    pd.load()
    # pd.print(
    #     timestamps=[0],
    #     minimum_count=2,
    # )
    return pd.data


def main():
    splitter_start_time = time.time()

    ps = PCAPSplitter(
        "test.pcap", split_size=10, maximum_count=200, callback=buffer_callback
    )
    results = ps.split()
    print(results)

    data = results.pop(0).result()
    for result in results:
        data = pcap_data_merge(data, result.result())
    splitter_end_time = time.time()

    # create a bogus dissector
    pd = PCAPDissector(
        None,
        bin_size=0,
        dissector_level=10,
        cache_results=False,
    )
    pd.data = data
    pd.print(
        timestamps=[0],
        minimum_count=10,
    )
    pd.save("test.pcap.pkl")

    # now compare it with a straight read to ensure the data results are the same
    normal_start_time = time.time()
    pd = PCAPDissector(
        "test.pcap",
        bin_size=0,
        dissector_level=10,
        cache_results=False,
    )
    pd.load()
    data2 = pd.data
    normal_end_time = time.time()

    assert data == data2
    print("got past assert -- all is well")
    print(f"time for splitter: {splitter_end_time - splitter_start_time}")
    print(f"time for normal:   {normal_end_time - normal_start_time}")


if __name__ == "__main__":
    main()

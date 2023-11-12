"""Loads a PCAP file and counts contents with various levels of storage"""

import io
import os
import multiprocessing
from traffic_taffy.dissector import PCAPDissector
from typing import List
import dpkt
from concurrent.futures import ProcessPoolExecutor, Future
from logging import debug, info


class PCAPSplitter:
    "Quickly reads a PCAP file and splits into multiple io.BytesIO streams"

    def __init__(
        self,
        pcap_file: str,
        callback=None,
        split_size: int = 0,
        maximum_count: int = 0,
        pcap_filter: str | None = None,
        maximum_cores: int | None = None,
    ) -> List[io.BytesIO]:
        self.pcap_file: str = pcap_file
        self.callback = callback
        self.split_size: int = split_size
        self.maximum_count: int = maximum_count
        self.pcap_filter: str | None = pcap_filter
        self.maximum_cores = maximum_cores

        self.header: bytes = None
        self.buffer: bytes = None
        self.packets_read: int = 0
        self.dpkt_data = None
        self.our_data = None
        self.results: List[io.BytesIO] = []
        self.process_pool = ProcessPoolExecutor()

        if not os.path.exists(self.pcap_file):
            raise ValueError(f"failed to find pcap file '{self.pcap_file}'")

    def set_split_size(self):
        "Attempt to calculate a reasonable split size"
        if self.split_size:
            info(f"split size already set to {self.split_size}")
            return self.split_size

        cores = multiprocessing.cpu_count()
        if self.maximum_cores and cores > self.maximum_cores:
            cores = self.maximum_cores

        if self.maximum_count and self.maximum_count > 0:
            # not ideal math, but better than nothing
            self.split_size = int(self.maximum_count / cores)
        else:
            if isinstance(self.our_data, io.BufferedReader):
                # raw uncompressed file
                divide_size = 1200
            else:
                # likely a compressed file
                divide_size = 5000

            # even worse math and assumes generally large packets
            stats = os.stat(self.pcap_file)
            file_size = stats.st_size
            self.split_size = int(file_size / divide_size / cores)
            debug(
                f"split info: {file_size=}, {divide_size=}, {cores=}, {self.split_size=}"
            )

        # even 1000 is kinda silly to split, but is better than nothing
        self.split_size = max(self.split_size, 1000)
        debug(f"setting PCAPSplitter split size to {self.split_size} for {cores} cores")

    def split(self) -> List[io.BytesIO] | List[Future]:
        "Does the actual reading and splitting"
        # open one for the dpkt reader and one for us independently
        self.our_data = PCAPDissector.open_maybe_compressed(self.pcap_file)
        self.dpkt_data = PCAPDissector.open_maybe_compressed(self.pcap_file)

        self.set_split_size()

        # read the first 24 bytes which is the pcap header
        self.header = self.our_data.read(24)

        # now process with dpkt to pull out each packet
        pcap = dpkt.pcap.Reader(self.dpkt_data)
        if self.pcap_filter:
            pcap.setfilter(self.pcap_filter)
        pcap.dispatch(self.maximum_count, self.dpkt_callback)

        # TODO: need to process the remaining bytes
        self.save_packets()

        self.process_pool.shutdown(wait=True, cancel_futures=False)

        return self.results

    def save_packets(self):
        "Saves the contents seen to this point into a new io.BytesIO"
        self.buffer = bytes(self.header)

        # read from our files current position to where the dpkt reader is
        bytes_to_read: int = self.dpkt_data.tell() - self.our_data.tell()
        self.buffer += self.our_data.read(bytes_to_read)

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

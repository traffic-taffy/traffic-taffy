from traffic_taffy.dissector import PCAPDissector, pcap_data_merge
from traffic_taffy.pcap_splitter import PCAPSplitter
from concurrent.futures import ProcessPoolExecutor
from logging import info
import copy


class PCAPDissectMany:
    def __init__(self, pcap_files, *args, **kwargs):
        self.pcap_files = pcap_files
        self.args = args
        self.kwargs = kwargs
        self.futures = {}

    def load_pcap_piece(self, pcap_io_buffer):
        kwargs = copy.copy(self.kwargs)
        # force false for actually loading
        kwargs["cache_results"] = False
        pd = PCAPDissector(
            pcap_io_buffer,
            *self.args,
            **self.kwargs,
        )
        pd.load()
        return pd.data

    def load_pcap(self, pcap_file, split_size=100000, maximum_count=0):
        # TODO: check caching availability here
        info(f"processing {pcap_file}")
        ps = PCAPSplitter(
            pcap_file,
            split_size=split_size,
            callback=self.load_pcap_piece,
            maximum_count=maximum_count,
        )
        results = ps.split()

        data = results.pop(0).result()
        for result in results:
            data = pcap_data_merge(data, result.result())
        return {"file": pcap_file, "data": data}

    def load_all(self):
        with ProcessPoolExecutor() as executor:
            results = executor.map(self.load_pcap, self.pcap_files)
            return results

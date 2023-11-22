from traffic_taffy.dissector import PCAPDissector, pcap_data_merge
from pcap_parallel import PCAPParallel
from concurrent.futures import ProcessPoolExecutor
from logging import info
import copy
import multiprocessing


class PCAPDissectMany:
    def __init__(self, pcap_files, *args, **kwargs):
        self.pcap_files = pcap_files
        self.args = args
        self.kwargs = kwargs
        self.futures = {}

        self.maximum_cores = self.kwargs.get("maximum_cores")
        if not self.maximum_cores:
            # since we're loading multiple files in parallel, reduce the
            # maximum number of cores available to the splitter
            # TODO: this may undercount due to int flooring()
            self.maximum_cores = int(multiprocessing.cpu_count() / len(self.pcap_files))

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

    def load_pcap(self, pcap_file, split_size=None, maximum_count=0):
        pd = PCAPDissector(
            pcap_file,
            *self.args,
            **self.kwargs,
        )
        data = pd.load_from_cache()
        if data:
            return {"file": pcap_file, "data": data}

        # TODO: check caching availability here
        info(f"processing {pcap_file}")
        ps = PCAPParallel(
            pcap_file,
            split_size=split_size,
            callback=self.load_pcap_piece,
            maximum_count=self.kwargs.get("maximum_count", 0),
            maximum_cores=self.maximum_cores,
        )
        results = ps.split()

        data = results.pop(0).result()
        for result in results:
            data = pcap_data_merge(data, result.result())

        PCAPDissector.calculate_metadata(data)

        if self.kwargs.get("cache_results"):
            # create a dissector just to save the cache
            # (we don't call load())
            pd = PCAPDissector(
                pcap_file,
                *self.args,
                **self.kwargs,
            )
            pd.data = data
            pd.save(pcap_file + ".pkl")

        return {"file": pcap_file, "data": data}

    def load_all(self):
        with ProcessPoolExecutor() as executor:
            results = executor.map(self.load_pcap, self.pcap_files)
            return results

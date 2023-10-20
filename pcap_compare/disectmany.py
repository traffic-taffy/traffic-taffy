from pcap_compare.disector import PCAPDisector
from concurrent.futures import ProcessPoolExecutor
from logging import info


class PCAPDisectMany:
    def __init__(self, pcap_files, *args, **kwargs):
        self.pcap_files = pcap_files
        self.args = args
        self.kwargs = kwargs

        self.futures = {}

    def load_pcap(self, pcap_file):
        pd = PCAPDisector(pcap_file, *self.args, **self.kwargs)
        info(f"reading {pcap_file}")
        return {"file": pcap_file, "data": pd.load()}

    def load_all(self):
        with ProcessPoolExecutor() as executor:
            results = executor.map(self.load_pcap, self.pcap_files)
            return results

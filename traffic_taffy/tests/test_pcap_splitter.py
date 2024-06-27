import os
import time
import logging
from logging import debug
from traffic_taffy.dissector import PCAPDissector, pcap_data_merge
from traffic_taffy.dissection import Dissection
from traffic_taffy.taffy_config import TaffyConfig
from pcap_parallel import PCAPParallel

test_pkl = "/tmp/test.pcap.pkl"

default_config = TaffyConfig(
    {
        "dissect": {
            "dissection_level": 10,
            "filter": None,
            "packet_count": 0,
            "cache_pcap_results": False,
            "bin_size": 1,
            "cache_file_suffix": "taffy",
            "ignore_list": [],
            "layers": [],
            "force_overwrite": False,
            "force_load": False,
        }
    }
)


def buffer_callback(pcap_io_buffer):
    pd = PCAPDissector(
        pcap_io_buffer,
        default_config,
    )
    pd.load()
    return pd.dissection.data


def test_pcap_splitter():
    logging.basicConfig(level="DEBUG", format="%(levelname)-10s:\t%(message)s")

    for test_pcap in [
        "test.pcap",
        "testgz.pcap.gz",
        "testbz2.pcap.bz2",
        "testxz.pcap.xz",
    ]:
        debug(f"===== trying to load {test_pcap} ====")
        if not os.path.exists(test_pcap):
            continue

        # clean up previous runs
        if os.path.exists(test_pkl):
            os.unlink(test_pkl)

        splitter_start_time = time.time()

        split_size = 100
        maximum_count = 0

        ps = PCAPParallel(
            test_pcap,
            split_size=split_size,
            callback=buffer_callback,
            maximum_count=maximum_count,
        )
        results = ps.split()

        data = results.pop(0).result()
        for result in results:
            data = pcap_data_merge(data, result.result())

        dissection = Dissection("BOGUS")
        dissection.data = data
        dissection.calculate_metadata()
        splitter_end_time = time.time()

        # create a bogus dissector
        pd = PCAPDissector(
            None,
            default_config,
        )
        pd.dissection = dissection
        dissection.save(test_pkl)
        assert os.path.exists(test_pkl)

        # now compare it with a straight read to ensure the data results are the same
        debug("----- starting singular -----")
        normal_start_time = time.time()
        pd = PCAPDissector(
            test_pcap,
            default_config,
        )
        pd.load()
        data2 = pd.dissection.data
        normal_end_time = time.time()

        assert data == data2
        debug("got past assert -- all is well")
        debug(f"time for splitter: {splitter_end_time - splitter_start_time}")
        debug(f"time for normal:   {normal_end_time - normal_start_time}")

        os.unlink(test_pkl)


if __name__ == "__main__":
    test_pcap_splitter()

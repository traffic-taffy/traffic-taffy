import os
import time
import logging
from logging import debug
from traffic_taffy.pcap_splitter import PCAPSplitter
from traffic_taffy.dissector import PCAPDissector, pcap_data_merge

test_pcap = "test.pcap"
test_pkl = "/tmp/test.pcap.pkl"


def buffer_callback(pcap_io_buffer):
    pd = PCAPDissector(
        pcap_io_buffer,
        bin_size=0,
        dissector_level=10,
        cache_results=False,
    )
    pd.load()
    return pd.data


def test_pcap_splitter():
    logging.basicConfig(level="DEBUG", format="%(levelname)-10s:\t%(message)s")
    if not os.path.exists(test_pcap):
        print(f"this test requires a {test_pcap} file to read and parse")

    # clean up previous runs
    if os.path.exists(test_pkl):
        os.unlink(test_pkl)

    splitter_start_time = time.time()

    split_size = 0
    maximum_count = 0

    ps = PCAPSplitter(
        test_pcap,
        split_size=split_size,
        callback=buffer_callback,
        maximum_count=maximum_count,
    )
    results = ps.split()

    data = results.pop(0).result()
    for result in results:
        data = pcap_data_merge(data, result.result())
        print("mergeed")
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
    pd.save(test_pkl)
    assert os.path.exists(test_pkl)

    # now compare it with a straight read to ensure the data results are the same
    debug("----- starting singular -----")
    normal_start_time = time.time()
    pd = PCAPDissector(
        test_pcap,
        bin_size=0,
        dissector_level=10,
        cache_results=False,
        maximum_count=maximum_count,
    )
    pd.load()
    data2 = pd.data
    normal_end_time = time.time()

    assert data == data2
    debug("got past assert -- all is well")
    debug(f"time for splitter: {splitter_end_time - splitter_start_time}")
    debug(f"time for normal:   {normal_end_time - normal_start_time}")

    os.unlink(test_pkl)


if __name__ == "__main__":
    test_pcap_splitter()

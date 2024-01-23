import os
from traffic_taffy.dissector_engine.dpkt import DissectionEngineDpkt
from traffic_taffy.dissection import Dissection


def test_dissector_load():
    from traffic_taffy.dissector import PCAPDissector

    pd = PCAPDissector("bogus")
    assert isinstance(pd, PCAPDissector)
    assert pd.pcap_file == "bogus"


def test_dissector_simple_callback():
    from traffic_taffy.dissector import PCAPDissector, PCAPDissectorLevel

    dpkt_engine = DissectionEngineDpkt("bogus")
    dpkt_engine.init_dissection()
    dpkt_engine.dissection.bin_size = 2
    dpkt_engine.dissector_level = PCAPDissectorLevel.COUNT_ONLY
    dpkt_engine.callback(10, b"")

    TOTAL_COUNT = Dissection.TOTAL_COUNT
    TOTAL_SUBKEY = Dissection.TOTAL_SUBKEY

    assert dpkt_engine.dissection.data == {
        0: {TOTAL_COUNT: {TOTAL_SUBKEY: 1}},
        10: {TOTAL_COUNT: {TOTAL_SUBKEY: 1}},
    }

    dpkt_engine.callback(12, b"")
    assert dict(dpkt_engine.dissection.data) == {
        0: {TOTAL_COUNT: {TOTAL_SUBKEY: 2}},
        10: {TOTAL_COUNT: {TOTAL_SUBKEY: 1}},
        12: {TOTAL_COUNT: {TOTAL_SUBKEY: 1}},
    }

    dpkt_engine.callback(11, b"")
    assert dpkt_engine.dissection.data == {
        0: {TOTAL_COUNT: {TOTAL_SUBKEY: 3}},
        10: {TOTAL_COUNT: {TOTAL_SUBKEY: 2}},
        12: {TOTAL_COUNT: {TOTAL_SUBKEY: 1}},
    }

    base_pcap = "/tmp/dissector-test.pcap"
    save_file = base_pcap + ".taffy"
    if os.path.exists(save_file):
        os.unlink(save_file)

    dpkt_engine.dissection.save(save_file)

    # create a new one to make sure it's blank
    pd = PCAPDissector(
        base_pcap,
        dissector_level=PCAPDissectorLevel.DETAILED,
        bin_size=20,
        cache_results=True,
    )

    pd.load()

    assert pd.dissection.data == {
        0: {TOTAL_COUNT: {TOTAL_SUBKEY: 3}},
        10: {TOTAL_COUNT: {TOTAL_SUBKEY: 2}},
        12: {TOTAL_COUNT: {TOTAL_SUBKEY: 1}},
    }

    os.unlink(save_file)


def test_dissector_scapy_callback():
    assert True

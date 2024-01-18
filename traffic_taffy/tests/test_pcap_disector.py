import os
from traffic_taffy.dissector_engine.dpkt import DissectionEngineDpkt


def test_dissector_load():
    from traffic_taffy.dissector import PCAPDissector

    pd = PCAPDissector("bogus")
    assert isinstance(pd, PCAPDissector)
    assert pd.data == {0: {}}


def test_dissector_simple_callback():
    from traffic_taffy.dissector import PCAPDissector, PCAPDissectorLevel

    pd = PCAPDissector(
        "bogus", dissector_level=PCAPDissectorLevel.COUNT_ONLY, bin_size=2
    )

    dpkt_engine = DissectionEngineDpkt("bogus")
    dpkt_engine.init_dissection()
    dpkt_engine.callback(10, b"")
    assert pd.data == {
        0: {pd.TOTAL_COUNT: {pd.TOTAL_SUBKEY: 1}},
        10: {pd.TOTAL_COUNT: {pd.TOTAL_SUBKEY: 1}},
    }

    pd.dpkt_callback(12, b"")
    assert dict(pd.data) == {
        0: {pd.TOTAL_COUNT: {pd.TOTAL_SUBKEY: 2}},
        10: {pd.TOTAL_COUNT: {pd.TOTAL_SUBKEY: 1}},
        12: {pd.TOTAL_COUNT: {pd.TOTAL_SUBKEY: 1}},
    }

    pd.dpkt_callback(11, b"")
    assert pd.data == {
        0: {pd.TOTAL_COUNT: {pd.TOTAL_SUBKEY: 3}},
        10: {pd.TOTAL_COUNT: {pd.TOTAL_SUBKEY: 2}},
        12: {pd.TOTAL_COUNT: {pd.TOTAL_SUBKEY: 1}},
    }

    save_file = "/tmp/dissector-test.pkl"
    if os.path.exists(save_file):
        os.unlink(save_file)

    pd.save(save_file)

    # create a new one to make sure it's blank
    pd = PCAPDissector(
        "bogusx", dissector_level=PCAPDissectorLevel.DETAILED, bin_size=20
    )

    pd.load_saved(save_file)

    assert pd.data == {
        0: {pd.TOTAL_COUNT: {pd.TOTAL_SUBKEY: 3}},
        10: {pd.TOTAL_COUNT: {pd.TOTAL_SUBKEY: 2}},
        12: {pd.TOTAL_COUNT: {pd.TOTAL_SUBKEY: 1}},
    }


def test_dissector_scapy_callback():
    assert True

import os


def test_disector_load():
    from pcap_compare.disector import PCAPDisector

    pd = PCAPDisector("bogus")
    assert isinstance(pd, PCAPDisector)
    assert pd.data == {0: {}}


def test_disector_simple_callback():
    from pcap_compare.disector import PCAPDisector, PCAPDisectorType

    pd = PCAPDisector("bogus", disector_type=PCAPDisectorType.DETAILED, bin_size=2)

    pd.dpkt_callback(10, b"")
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

    save_file = "/tmp/disector-test.pkl"
    if os.path.exists(save_file):
        os.unlink(save_file)

    pd.save(save_file)

    # create a new one to make sure it's blank
    pd = PCAPDisector("bogusx", disector_type=PCAPDisectorType.DETAILED, bin_size=20)

    pd.load_saved(save_file)

    assert pd.data == {
        0: {pd.TOTAL_COUNT: {pd.TOTAL_SUBKEY: 3}},
        10: {pd.TOTAL_COUNT: {pd.TOTAL_SUBKEY: 2}},
        12: {pd.TOTAL_COUNT: {pd.TOTAL_SUBKEY: 1}},
    }


def test_disector_scapy_callback():
    assert True

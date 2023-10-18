def test_disector_load():
    from pcap_compare.pcap_disector import PCAPDisector, PCAPDisectorType
    pd = PCAPDisector("bogus")
    assert isinstance(pd, PCAPDisector)
    assert pd.data == {}

def test_disector_callback():
    from collections import Counter
    from pcap_compare.pcap_disector import PCAPDisector, PCAPDisectorType
    pd = PCAPDisector("bogus", disector_type = PCAPDisectorType.DETAILED,
                      bin_size = 2)

    pd.dpkt_callback(10, b'')
    assert pd.data == {0: {pd.TOTAL_COUNT: 1},
                       10: {pd.TOTAL_COUNT: 1}}
    
    pd.dpkt_callback(12, b'')
    assert dict(pd.data) == {0: {pd.TOTAL_COUNT: 2},
                             10: {pd.TOTAL_COUNT: 1},
                             12: {pd.TOTAL_COUNT: 1}}


    pd.dpkt_callback(11, b'')
    assert pd.data == {0: {pd.TOTAL_COUNT: 3},
                       10: {pd.TOTAL_COUNT: 2},
                       12: {pd.TOTAL_COUNT: 1}}

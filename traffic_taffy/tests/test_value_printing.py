from traffic_taffy.dissector import PCAPDissector


def test_printable():
    assert (
        PCAPDissector.make_printable("Ethernet.IP.dst", b"\x7f\x00\x00\x01")
        == "127.0.0.1"
    )

    assert PCAPDissector.make_printable("badtype", b"\x7f\x00\x00\x01") == "0x7f000001"

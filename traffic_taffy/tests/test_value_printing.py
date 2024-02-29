from traffic_taffy.dissection import Dissection


def test_printable():
    assert (
        Dissection.make_printable("Ethernet_IP_dst", b"\x7f\x00\x00\x01") == "127.0.0.1"
    )

    assert Dissection.make_printable("badtype", b"\x7f\x00\x00\x01") == "0x7f000001"

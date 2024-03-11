from traffic_taffy.dissection import Dissection
from traffic_taffy.dissector import POST_DISSECT_HOOK
from traffic_taffy.hooks import call_hooks


def test_splitter_module():
    dissection = Dissection("bogus")
    dissection.incr("foo", "bar")
    dissection.incr("foo_qname", "www.example.com")
    dissection.incr("foo_mname", "www.example.co.uk")

    assert dissection.data[0] == {
        "foo": {"bar": 1},
        "foo_qname": {"www.example.com": 1},
        "foo_mname": {"www.example.co.uk": 1},
    }

    call_hooks(POST_DISSECT_HOOK, dissection)
    test_result = {
        "foo": {"bar": 1},
        "foo_mname": {"www.example.co.uk": 1},
        "foo_mname_prefix": {"www": 1},
        "foo_mname_domain": {"example.co.uk": 1},
        "foo_mname_psl": {"co.uk": 1},
        "foo_qname": {"www.example.com": 1},
        "foo_qname_prefix": {"www": 1},
        "foo_qname_domain": {"example.com": 1},
        "foo_qname_psl": {"com": 1},
    }
    assert dissection.data[0] == test_result

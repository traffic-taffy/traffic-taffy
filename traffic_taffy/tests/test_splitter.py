from traffic_taffy.dissection import Dissection
from traffic_taffy.dissector import POST_DISSECT_HOOK
from traffic_taffy.hooks import call_hooks
import traffic_taffy.hooks.psl


def test_splitter_module():
    dissection = Dissection("bogus")
    dissection.incr("foo", "bar")
    dissection.incr("foo_qname", "www.example.com")
    dissection.incr("foo_qname", "www.example.net")
    dissection.incr("foo_mname", "www.example.co.uk")
    dissection.incr("foo_qname", "bogus.__doesntexist")

    # bogus to avoid ruff removing the import
    traffic_taffy.hooks.psl.splitter = traffic_taffy.hooks.psl.splitter

    assert dissection.data[0] == {
        "foo": {"bar": 1},
        "foo_qname": {
            "www.example.com": 1,
            "www.example.net": 1,
            "bogus.__doesntexist": 1,
        },
        "foo_mname": {"www.example.co.uk": 1},
    }

    call_hooks(POST_DISSECT_HOOK, dissection)

    test_result = {
        "foo": {"bar": 1},
        "foo_mname": {"www.example.co.uk": 1},
        "foo_mname_prefix": {"www": 1},
        "foo_mname_domain": {"example.co.uk": 1},
        "foo_mname_psl": {"co.uk": 1},
        "foo_qname": {
            "www.example.com": 1,
            "www.example.net": 1,
            "bogus.__doesntexist": 1,
        },
        "foo_qname_prefix": {"www": 2},
        "foo_qname_domain": {"example.com": 1, "example.net": 1},
        "foo_qname_psl": {"com": 1, "net": 1},
    }
    assert dissection.data[0] == test_result

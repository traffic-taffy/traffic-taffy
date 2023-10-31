from traffic_taffy.dissectorresults import DissectorResults


def test_dissector_results_isa():
    A = DissectorResults()
    assert isinstance(A, DissectorResults) is True


def test_dissector_results_storage():
    A = DissectorResults()
    A["a"]["b"] = 4
    A["c"]["d"] += 1
    A["c"]["d"] += 1

    assert A["a"]["b"] == 4
    assert A["c"]["d"] == 2

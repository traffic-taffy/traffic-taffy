from traffic_taffy.config import Config
from traffic_taffy.taffy_config import TaffyConfig, taffy_default


def test_multi_config():
    c1 = Config()
    c2 = Config()

    c1["foo"] = 2
    c2["foo"] = 3
    assert c1["foo"] == 2


def test_global_config():
    c1 = TaffyConfig()
    c2 = TaffyConfig()

    c1["foo"] = 2
    c2["foo"] = 3
    assert c1["foo"] == 3


def test_defaults():
    taffy_default("a", "b")

    c = TaffyConfig()
    assert c["a"] == "b"

    c["a"] = "c"  # override
    assert c["a"] == "c"

    taffy_default("a", "d")  # ignore overrides
    assert c["a"] == "c"

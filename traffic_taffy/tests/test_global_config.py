from traffic_taffy.config import Config
from traffic_taffy.taffy_config import TaffyConfig


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

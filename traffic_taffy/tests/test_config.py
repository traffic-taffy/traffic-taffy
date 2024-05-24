from io import StringIO
from traffic_taffy.config import Config


def test_loading():
    contents = StringIO(
        """
    name: foo
    value: bar
    arry:
      - 1
      - 2
    """
    )

    cfg = Config()
    cfg.load(contents)
    assert cfg["name"] == "foo"
    assert cfg["arry"][0] == 1  # truly sic!

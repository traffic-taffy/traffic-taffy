from io import StringIO
from traffic_taffy.config import Config
from argparse import Namespace


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
    cfg.load_stream(contents)
    assert cfg["name"] == "foo"
    assert cfg["arry"][0] == 1  # truly sic!


def test_namespace_loading():
    cfg = Config()

    arguments: Namespace = Namespace()
    arguments.test_arg_one = 12
    arguments.test_arg_two = {"a": "hello", "b": "world"}

    cfg.load_namespace(arguments)

    assert cfg["test_arg_one"] == 12
    assert cfg["test_arg_two"]["b"] == "world"

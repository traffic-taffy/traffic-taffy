from io import StringIO
from traffic_taffy.config import Config
from argparse import Namespace
from tempfile import NamedTemporaryFile

from argparse import ArgumentParser

TESTCONFIG: str = """
name: foo
value: bar
arry:
  - 1
  - 2
"""


def test_loading():
    contents = StringIO(TESTCONFIG)

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


def test_as_namespace():
    contents = StringIO(TESTCONFIG)

    cfg = Config()
    cfg.load_stream(contents)
    assert cfg["name"] == "foo"
    assert cfg["arry"][0] == 1  # truly sic!

    args = cfg.as_namespace()

    assert args.name == "foo"
    assert args.arry[0] == 1


def test_namespace_loading_and_mapping():
    cfg = Config()

    arguments: Namespace = Namespace()
    arguments.test_arg_one = 12
    arguments.test_arg_two = {"a": "hello", "b": "world"}

    remap: dict = {"test_arg_one": "new_arg_one"}

    cfg.load_namespace(arguments, mapping=remap)

    assert cfg["new_arg_one"] == 12
    assert cfg["test_arg_two"]["b"] == "world"

    assert "test_arg_one" not in cfg


def test_config_commandline_option():
    cfg = Config()

    with NamedTemporaryFile("w", suffix="yml") as fileh:
        fileh.write(TESTCONFIG)
        fileh.flush()

        cfg.read_configfile_from_arguments(
            ["foo", "bar", "-in-the-way", "--config", fileh.name, "--other", "-arg"]
        )

        assert cfg["name"] == "foo"
        assert cfg["arry"][0] == 1


def test_expected_full_usage():
    # Create configuration in a yaml file
    with NamedTemporaryFile("w", suffix="yml") as fileh:
        fileh.write("question: 'how many roads must a man walk down?'\n")
        fileh.write("reference: hitchhikers\n")
        fileh.write("options:\n  - 1\n  - 2\n  - 3\n")
        fileh.flush()

        # set some application hard-code defaults
        cfg = Config()
        cfg["answer"] = 42
        cfg["options"] = ["a", "b", "c"]

        assert cfg == {"answer": 42, "options": ["a", "b", "c"]}

        # define the arguments we want to pass (potentially overriding other variables)
        passed_arguments = [
            "--question",
            "What do you get when you multiply six by seven?",
            "--config",
            fileh.name,
            "-r",
            "The guide",
        ]

        # now parse these to just read the config file
        cfg.read_configfile_from_arguments(passed_arguments)

        # ensure the configuration has been updated from the file contents, but not CLI args

        assert cfg == {
            "answer": 42,  # note: same
            "options": [1, 2, 3],  # note: overwritten
            "question": "how many roads must a man walk down?",  # note: same
            "reference": "hitchhikers",  # note: same
        }

        # set up the command line options
        parser = ArgumentParser()

        parser.add_argument("-q", "--question", default=cfg["question"], type=str)
        parser.add_argument("-a", "--answer", default=cfg["answer"], type=int)
        parser.add_argument(
            "-o", "--options", default=cfg["options"], nargs="+", type=int
        )
        parser.add_argument("-r", "--reference", default=cfg["reference"], type=str)
        parser.add_argument("-c", "--config", type=str)
        parser.add_argument("--only-unused-argument", "--", type=str)

        args = parser.parse_args(passed_arguments)
        cfg.load_namespace(args)

        del cfg[
            "config"
        ]  # this will always be random tmp file and we don't need to check it
        assert (
            cfg
            == {
                "answer": 42,  # note: still a default
                "options": [1, 2, 3],  # note: from config
                "question": "What do you get when you multiply six by seven?",  # note: from cli
                "reference": "The guide",  # note: from cli
                "only_unused_argument": None,
            }
        )

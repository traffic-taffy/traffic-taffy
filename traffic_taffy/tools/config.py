"""Performs generic dissection of a PCAP file."""
import sys
import logging
import yaml
from traffic_taffy.taffy_config import TaffyConfig
from rich_argparse import RichHelpFormatter
from argparse import ArgumentParser, Namespace


def main() -> None:
    """Dissect a pcap file and report contents."""

    def parse_args() -> Namespace:
        """Parse the command line arguments."""

        config: TaffyConfig = TaffyConfig()
        config.config_option_names = ["-y", "--config"]
        config["log_level"] = "info"

        config.read_configfile_from_arguments(sys.argv)

        parser = ArgumentParser(
            formatter_class=RichHelpFormatter,
            description=__doc__,
            epilog="Example Usage: taffy-config > defaults.yml",
        )

        parser.add_argument(
            "-y",
            "--config",
            default=None,
            type=str,
            help="Configuration file (YAML) to load.",
        )

        parser.add_argument(
            "--log-level",
            "--ll",
            default="info",
            help="Define the logging verbosity level (debug, info, warning, error, fotal, critical).",
        )

        args = parser.parse_args()
        log_level = args.log_level.upper()
        logging.basicConfig(level=log_level, format="%(levelname)-10s:\t%(message)s")

        config.load_namespace(args)
        return config

    config = parse_args()
    config.as_namespace()

    print(yaml.dump(config))


if __name__ == "__main__":
    main()

"""Performs generic dissection of a PCAP file."""
import sys
import logging
import yaml
from traffic_taffy.taffy_config import TaffyConfig, TT_CFG
from rich_argparse import RichHelpFormatter
from argparse import ArgumentParser, Namespace

# these force configuration token loading in a way ruff won't "fix"
from traffic_taffy.dissector import TTD_CFG as TTD_CFG
from traffic_taffy.compare import TTC_CFG as TTC_CFG
from traffic_taffy.graph import TTG_CFG as TTG_CFG
from traffic_taffy.tools.compare import compare_parse_args as compare_parse_args


# we try to load a number of modules, but if the missing requirements aren't available
# we don't fail here
try:
    from traffic_taffy.dissector_engine.scapy import (
        DissectionEngineScapy as DissectionEngineScapy,
    )
except ModuleNotFoundError:
    logging.debug("scapy module not loadable")

try:
    from traffic_taffy.hooks.ip2asn import ip_to_asn as ip_to_asn
except ModuleNotFoundError:
    logging.debug("ip2asn module not loadable")

try:
    from traffic_taffy.hooks.psl import split_dns_names as split_dns_names
except ModuleNotFoundError:
    logging.debug("psl module not loadable")


def taffy_config_parse_args() -> Namespace:
    """Parse the command line arguments."""

    config: TaffyConfig = TaffyConfig()
    config.config_option_names = ["-y", "--config"]
    config[TT_CFG.LOG_LEVEL] = "info"

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


def main() -> None:
    """Dissect a pcap file and report contents."""

    config = taffy_config_parse_args()

    print(yaml.dump(dict(config)))


if __name__ == "__main__":
    main()

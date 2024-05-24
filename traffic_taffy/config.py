"""A helper class to store a generic set of configuration as a dict"""

from enum import Enum
from typing import TextIO, Dict, Any
from argparse import Namespace


class ConfigStyles(Enum):
    YAML = "yaml"
    TOML = "toml"
    # TODO(hardaker): support "any" at some point to determine type at run-time


class Config(dict):
    """A generic configuration storage class."""

    def __init__(self):
        pass

    def load_stream(
        self, config_handle: TextIO, style: ConfigStyles = ConfigStyles.YAML
    ):
        """Import a set of configuration from a IO stream."""
        if style == ConfigStyles.YAML:
            import yaml

            contents = yaml.safe_load(config_handle)

        # TODO(hardaker): support TOML

        self.update(contents)

    def load_file(self, config_file: str, style: ConfigStyles = ConfigStyles.YAML):
        """Load a configuration file from a filename"""
        self.load_stream(open(config_file))

    def load_namespace(
        self, namespace: Namespace, mapping: Dict[str, Any] | None = None
    ):
        """Load the contents of a namespace into configuration."""
        values = vars(namespace)
        if mapping:
            values = {mapping.get(key, key): value for key, value in values.items()}
        self.update(values)

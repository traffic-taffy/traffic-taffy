"""A helper class to store a generic set of configuration as a dict"""

from enum import Enum
from typing import TextIO
from argparse import Namespace


class ConfigStyles(Enum):
    YAML = "yaml"
    TOML = "toml"


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

        self.update(contents)

    def load_namespace(self, namespace: Namespace):
        """Load the contents of a namespace into configuration."""
        values = vars(namespace)
        self.update(values)

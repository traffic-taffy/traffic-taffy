"""A helper class to store a generic set of configuration as a dict"""

from enum import Enum
from typing import TextIO


class ConfigStyles(Enum):
    YAML = "yaml"
    TOML = "toml"


class Config(dict):
    """A generic configuration storage class."""

    def __init__(self):
        pass

    def load(self, config_handle: TextIO, style: ConfigStyles = ConfigStyles.YAML):
        """Import a set of configuration from a IO stream."""
        if style == ConfigStyles.YAML:
            import yaml

            contents = yaml.safe_load(config_handle)

        self.update(contents)

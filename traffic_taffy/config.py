"""A helper class to store a generic set of configuration as a dict."""

from __future__ import annotations
from enum import Enum
from typing import TextIO, Dict, Any, TYPE_CHECKING
from path import Path

if TYPE_CHECKING:
    from argparse import Namespace


class ConfigStyles(Enum):
    """A set of configuration types."""

    YAML = "yaml"
    TOML = "toml"
    # TODO(hardaker): support "any" at some point to determine type at run-time


class Config(dict):
    """A generic configuration storage class."""

    def __init__(self):
        """Create an configuration object to store collected data in."""

    def load_stream(
        self, config_handle: TextIO, style: ConfigStyles = ConfigStyles.YAML
    ) -> None:
        """Import a set of configuration from a IO stream."""
        if style == ConfigStyles.YAML:
            import yaml

            contents = yaml.safe_load(config_handle)

        # TODO(hardaker): support TOML

        self.update(contents)

    def load_file(
        self, config_file: str, style: ConfigStyles = ConfigStyles.YAML
    ) -> None:
        """Load a configuration file from a filename."""
        self.load_stream(Path.open(config_file), style=style)

    def load_namespace(
        self, namespace: Namespace, mapping: Dict[str, Any] | None = None
    ) -> None:
        """Load the contents of a namespace into configuration."""
        values = vars(namespace)
        if mapping:
            values = {mapping.get(key, key): value for key, value in values.items()}
        self.update(values)

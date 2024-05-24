"""A helper class to store a generic set of configuration as a dict."""

from __future__ import annotations
from enum import Enum
from typing import TextIO, Dict, List, Any, TYPE_CHECKING
from pathlib import Path
from logging import error

if TYPE_CHECKING:
    from argparse import Namespace


class ConfigStyles(Enum):
    """A set of configuration types."""

    YAML = "yaml"
    TOML = "toml"
    # TODO(hardaker): support "any" at some point to determine type at run-time


class Config(dict):
    """A generic configuration storage class."""

    default_config_option_names = ["--config"]

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

    def read_configfile_from_arguments(
        self,
        argv: List[str],
        config_option_names: str | List[str] = default_config_option_names,
    ) -> None:
        """Scan an list of arguments for configuration file(s) and load them."""
        if isinstance(config_option_names, str):
            config_option_names = [config_option_names]

        for n, item in enumerate(argv):
            if item in config_option_names:
                if len(argv) == n:
                    error(f"no argument supplied after '{item}'")
                    raise ValueError

                if argv[n + 1].startswith("-"):
                    error(f"The argument after '{item}' seems to be another argument")
                    raise ValueError

                filename = argv[n + 1]

                if not Path(filename).is_file():
                    error(
                        f"The filename after '{item}' does not exist or is not a file"
                    )
                    raise ValueError

                self.load_file(filename)

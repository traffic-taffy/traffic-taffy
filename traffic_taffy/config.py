"""A helper class to store a generic set of configuration as a dict."""

from __future__ import annotations
from enum import Enum
from typing import TextIO, Dict, List, Any
from pathlib import Path
from logging import error
from argparse import Namespace
from dotnest import DotNest


class ConfigStyles(Enum):
    """A set of configuration types."""

    YAML = "yaml"
    TOML = "toml"
    # TODO(hardaker): support "any" at some point to determine type at run-time


class Config(dict):
    """A generic configuration storage class."""

    def __init__(self, *args, **kwargs):
        """Create an configuration object to store collected data in."""
        self._config_option_names = ["--config"]
        self.dotnest = DotNest(self, allow_creation=True)
        super().__init__(*args, **kwargs)

    @property
    def config_option_names(self) -> List[str]:
        """The list of configuration file arguments to use/look for."""
        return self._config_option_names

    @config_option_names.setter
    def config_option_names(self, newlist: str | List[str]) -> None:
        if isinstance(newlist, str):
            newlist = [newlist]

        self._config_option_names = newlist

    def deep_update(self, ref: dict, new_content: dict):
        for key in new_content:
            if key in ref and isinstance(ref[key], dict):
                self.deep_update(ref[key], new_content[key])
            else:
                ref[key] = new_content[key]

    def load_stream(
        self, config_handle: TextIO, style: ConfigStyles = ConfigStyles.YAML
    ) -> None:
        """Import a set of configuration from a IO stream."""
        if style == ConfigStyles.YAML:
            import yaml

            contents = yaml.safe_load(config_handle)

        # TODO(hardaker): support TOML
        self.deep_update(self, contents)

    def load_file(
        self, config_file: str, style: ConfigStyles = ConfigStyles.YAML
    ) -> None:
        """Load a configuration file from a filename."""
        self.load_stream(Path.open(config_file), style=style)

    def load_namespace(
        self, namespace: Namespace, mapping: Dict[str, Any] | None = None
    ) -> None:
        """Load the contents of an argparse Namespace into configuration."""
        values = vars(namespace)
        if mapping:
            values = {mapping.get(key, key): value for key, value in values.items()}
        self.update(values)

    def read_configfile_from_arguments(
        self,
        argv: List[str],
    ) -> None:
        """Scan an list of arguments for configuration file(s) and load them."""
        # TODO(hardaker): convert this to argparse's parse known feature
        # aka replace using stackoverflow answer to 3609852

        for n, item in enumerate(argv):
            if item in self.config_option_names:
                if len(argv) == n:
                    error(f"no argument supplied after '{item}'")
                    raise ValueError

                if argv[n + 1].startswith("-"):
                    error(f"The argument after '{item}' seems to be another argument")
                    raise ValueError

                filename = argv[n + 1]

                if "=" in filename:
                    (left, right) = filename.split("=")
                    left = left.strip()
                    right = right.strip()
                    self.set_dotnest(left, right)
                    continue

                if not Path(filename).is_file():
                    error(
                        f"The filename after '{item}' does not exist or is not a file"
                    )
                    raise ValueError

                self.load_file(filename)

    def as_namespace(self) -> Namespace:
        """Convert the configuration (back) into a argparse Namespace."""
        namespace = Namespace()
        for item, value in self.items():
            setattr(namespace, item, value)

        return namespace

    def dump(self):
        """Dumps the current configuration into a YAML format."""
        import yaml

        print(yaml.dump(self))

    def set_dotnest(self, parameter: str, value: Any):
        self.dotnest.set(parameter, value)

    def get_dotnest(
        self, parameter: str, default: Any = None, return_none: bool = True
    ):
        result = self.dotnest.get(parameter, return_none=return_none)
        if result is not None:
            return result
        return default

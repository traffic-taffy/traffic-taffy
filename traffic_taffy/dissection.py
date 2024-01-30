"""A Dissection class stores the results of a PCAP enumeration."""

from __future__ import annotations
import os
from collections import defaultdict, Counter
from typing import Any
from logging import debug, info, error, warning
from enum import Enum
import msgpack
import ipaddress
from typing import List
from copy import deepcopy


class PCAPDissectorLevel(Enum):
    """Enumeration of supported dissection levels."""

    COUNT_ONLY = 1
    THROUGH_IP = 2
    DETAILED = 10


class Dissection:
    """Class to store the data from an enumerated pcap."""

    DISSECTION_KEY: str = "PCAP_DISSECTION_VERSION"
    DISSECTION_VERSION: int = 7

    TOTAL_COUNT: str = "__TOTAL__"
    TOTAL_SUBKEY: str = "packet"
    WIDTH_SUBKEY: str = "__WIDTH__"
    NEW_RIGHT_SUBKEY: str = "__NEW_VALUES__"

    def __init__(
        self: Dissection,
        pcap_file: str,
        pcap_filter: str | None = None,
        maximum_count: int = 0,
        bin_size: int = 0,
        dissector_level: PCAPDissectorLevel = PCAPDissectorLevel.DETAILED,
        cache_file_suffix: str = "taffy",
        ignore_list: list = [],
        *args: list,
        **kwargs: dict,
    ) -> Dissection:
        """Create a Dissection instance."""
        self.pcap_file = pcap_file
        self.bin_size = bin_size
        self.cache_file_suffix = cache_file_suffix
        self._data = defaultdict(Dissection.subdict_producer)
        self._timestamp = 0
        self.dissector_level = dissector_level
        self.maximum_count = maximum_count
        self.pcap_filter = pcap_filter
        self.ignore_list = ignore_list

        self.parameters = [
            "pcap_file",
            "bin_size",
            "dissector_level",
            "pcap_filter",
            "maximum_count",
            "ignore_list",
        ]
        self.settable_from_cache = ["bin_size", "dissector_level", "maximum_count"]

    def clone(self: Dissection) -> Dissection:
        """Clone a second dissection instance from another."""
        newd = Dissection(
            self.pcap_file,
            self.pcap_filter,
            self.maximum_count,
            self.bin_size,
            self.dissector_level,
            self.cache_file_suffix,
            deepcopy(self.ignore_list),
        )
        newd.data = deepcopy(self.data)
        newd.timestamp = self.timestamp
        return newd

    @property
    def timestamp(self) -> int:
        return self._timestamp

    @timestamp.setter
    def timestamp(self: Dissection, newval):
        self._timestamp = newval

    @property
    def data(self: Dissection) -> dict:
        """The raw data in this dissection."""
        return self._data

    @data.setter
    def data(self: Dissection, newval):
        self._data = newval

    @property
    def pcap_file(self: Dissection):
        """The PCAP file name of this dissection"""
        return self._pcap_file

    @pcap_file.setter
    def pcap_file(self: Dissection, newval):
        self._pcap_file = newval

    def incr(self: Dissection, key: str, value: Any, count: int = 1):
        """Increase one field within the counter."""
        # always save a total count at the zero bin
        # note: there should be no recorded tcpdump files from 1970 Jan 01 :-)
        self.data[0][key][value] += count
        if self.timestamp:
            if self.timestamp not in self.data:
                self.data[self.timestamp] = defaultdict(Counter)
            self.data[self.timestamp][key][value] += count

    def calculate_metadata(self: Dissection) -> None:
        """Calculate thing like the number of value entries within each key/subkey."""
        # TODO: do we do this with or without key and value matches?
        for timestamp in self.data.keys():
            for key in self.data[timestamp]:
                if self.WIDTH_SUBKEY in self.data[timestamp][key]:
                    # make sure to avoid counting itself
                    del self.data[timestamp][key][self.WIDTH_SUBKEY]
                self.data[timestamp][key][self.WIDTH_SUBKEY] = len(
                    self.data[timestamp][key]
                )

                if self.NEW_RIGHT_SUBKEY in self.data[timestamp][key]:
                    # don't count the NEW subkey either
                    self.data[timestamp][key] -= 1

    def merge(self: Dissection, other_dissection) -> None:
        "merges counters in two dissections into self -- note destructive to self"
        for timestamp in other_dissection.data:
            for key in other_dissection.data[timestamp]:
                for subkey in other_dissection.data[timestamp][key]:
                    # TODO: this is horribly inefficient
                    if timestamp not in self.data:
                        self.data[timestamp] = defaultdict(Counter)
                    elif key not in self.data[timestamp]:
                        self.data[timestamp][key] = Counter()
                    elif (
                        isinstance(self.data[timestamp][key], dict)
                        and subkey not in self.data[timestamp][key]
                    ):
                        self.data[timestamp][key][subkey] = 0
                    self.data[timestamp][key][subkey] += other_dissection.data[
                        timestamp
                    ][key][subkey]

    def merge_all(self: Dissection, other_dissections: List[Dissection]) -> None:
        for dissection in other_dissections:
            self.merge(dissection)

    @staticmethod
    def subdict_producer():
        return defaultdict(Counter)

    #
    # Loading / Saving
    #

    def load_from_cache(
        self: Dissection, force_overwrite: bool = False, force_load: bool = True
    ) -> dict | None:
        if not self.pcap_file or not isinstance(self.pcap_file, str):
            return None
        if not os.path.exists(self.pcap_file + self.cache_file_suffix):
            return None

        cached_file = self.pcap_file + self.cache_file_suffix
        cached_contents = self.load_saved(cached_file, dont_overwrite=True)

        ok_to_load = True

        if cached_contents[self.DISSECTION_KEY] != self.DISSECTION_VERSION:
            debug(
                "dissection cache version ({cached_contents[self.DISSECTION_KEY]}) differs from code version {self.DISSECTION_VERSION}"
            )
            ok_to_load = False

        # a zero really is a 1 since bin(0) still does int(timestamp)
        if (
            cached_contents["parameters"]["bin_size"] == 0
            or cached_contents["parameters"]["bin_size"] is None
        ):
            cached_contents["parameters"]["bin_size"] = 1

        for parameter in self.parameters:
            specified = getattr(self, parameter)
            cached = cached_contents["parameters"][parameter]

            if not specified and parameter in self.settable_from_cache:
                # inherit from the cache
                setattr(self, parameter, cached)
                continue

            if specified and specified != cached:
                # special checks for certain types of parameters:

                if parameter == "dissector_level" and specified <= cached:
                    # loading a more detailed cache is ok
                    continue

                if parameter == "pcap_file" and os.path.basename(
                    specified
                ) == os.path.basename(cached):
                    # as long as the basename is ok, we'll assume it's a different path
                    continue

                error(
                    f"cache parameter '{parameter}' doesn't match: required={specified} != cached={cached}"
                )
                ok_to_load = False

        if ok_to_load:
            info(f"loading cached pcap contents from {cached_file}")
            self.load_saved_contents(cached_contents)
            return self

        if force_overwrite:
            info("forced continuing without loading the cache")
            return None

        if force_load:
            warning(
                f"cache file '{cached_file}' supposedly invalid -- attempting to load anyway"
            )
            self.load_saved_contents(cached_contents)
            return self

        error(f"Failed to load cached data for {self.pcap_file} due to differences")
        error("refusing to continue -- remove the cache to recreate it")
        raise ValueError(
            "INCOMPATIBLE CACHE: remove the cache or don't use it to continue"
        )

    def save_to_cache(self: Dissection, where: str | None = None) -> None:
        if not where and self.pcap_file and isinstance(self.pcap_file, str):
            where = self.pcap_file + self.cache_file_suffix
        if where:
            self.save(where)

    def save(self: Dissection, where: str) -> None:
        "Saves a generated dissection to a msgpack file"

        # wrap the report in a version header
        versioned_cache = {
            self.DISSECTION_KEY: self.DISSECTION_VERSION,
            "file": self.pcap_file,
            "parameters": {},
            "dissection": self.data,
        }

        for parameter in self.parameters:
            versioned_cache["parameters"][parameter] = getattr(self, parameter)
            # TODO: fix this hack

            # basically, bin_size of 0 is 1...  but it may be faster
            # to leave it at zero to avoid the bin_size math of 1,
            # which is actually a math noop that will still consume
            # cycles.  We save it as 1 though since the math is past
            # us and a 1 value is more informative to the user.
            if parameter == "bin_size" and self.bin_size == 0:
                versioned_cache["parameters"][parameter] = 1

            if parameter == "dissector_level" and isinstance(
                versioned_cache["parameters"][parameter], PCAPDissectorLevel
            ):
                versioned_cache["parameters"][parameter] = versioned_cache[
                    "parameters"
                ][parameter].value

        # msgpack can't store sets
        versioned_cache["parameters"]["ignore_list"] = list(
            versioned_cache["parameters"]["ignore_list"]
        )

        # save it
        info(f"caching PCAP data to '{where}'")
        msgpack.dump(versioned_cache, open(where, "wb"))

    def load_saved_contents(self: Dissection, versioned_cache):
        # set the local parameters from the cache
        for parameter in self.parameters:
            setattr(self, parameter, versioned_cache["parameters"][parameter])

        # load the data
        self.data = versioned_cache["dissection"]

    def load_saved(self: Dissection, where: str, dont_overwrite: bool = False) -> dict:
        "Loads a previous saved report from a file instead of re-parsing pcaps"
        contents = msgpack.load(open(where, "rb"), strict_map_key=False)

        # convert the ignore list to a set (msgpack doesn't do sets)
        contents["parameters"]["ignore_list"] = set(
            contents["parameters"]["ignore_list"]
        )

        # check that the version header matches something we understand
        if contents[self.DISSECTION_KEY] != self.DISSECTION_VERSION:
            raise ValueError(
                "improper saved dissection version: report version = "
                + str(contents[self.DISSECTION_KEY])
                + ", our version: "
                + str(self.DISSECTION_VERSION)
            )

        if not dont_overwrite:
            self.load_saved_contents(contents)

        return contents

    def find_data(
        self: Dissection,
        timestamps: List[int] | None = None,
        match_string: str | None = None,
        match_value: str | None = None,
        minimum_count: int | None = None,
        make_printable: bool = False,
    ):
        data = self.data

        if not timestamps:
            timestamps = data.keys()

        # find timestamps/key values with at least one item above count
        # TODO: we should really use pandas for this
        usable = defaultdict(set)
        for timestamp in timestamps:
            for key in data[timestamp]:
                # if they requested a match string
                if match_string and match_string not in key:
                    continue

                # ensure at least one of the count valuse for the
                # stream gets above minimum_count
                for subkey, count in data[timestamp][key].items():
                    if (
                        not minimum_count
                        or minimum_count
                        and abs(count) > minimum_count
                    ):
                        usable[key].add(subkey)

        # TODO: move the timestamp inside the other fors for faster
        # processing of skipped key/subkeys
        for timestamp in timestamps:
            for key in sorted(data[timestamp]):
                if key not in usable:
                    continue

                for subkey, count in sorted(
                    data[timestamp][key].items(), key=lambda x: x[1], reverse=True
                ):
                    # check that this subkey can be usable at all
                    if subkey not in usable[key]:
                        continue

                    if make_printable:
                        subkey = Dissection.make_printable(key, subkey)
                        count = Dissection.make_printable(None, count)

                    if match_value and match_value not in subkey:
                        continue

                    yield (timestamp, key, subkey, count)

    @staticmethod
    def make_printable(value_type: str, value: Any) -> str:
        try:
            if isinstance(value, bytes):
                if value_type in Dissection.display_transformers:
                    value = str(Dissection.display_transformers[value_type](value))
                else:
                    value = "0x" + value.hex()
            else:
                value = str(value)
        except Exception:
            if isinstance(value, bytes):
                value = "0x" + value.hex()
            else:
                value = "[unprintable]"
        if len(value) > 40:
            value = value[0:40] + "..."  # truncate to reasonable
        return value

    @staticmethod
    def print_mac_address(value):
        "Converts bytes to ethernet mac style address"

        # TODO: certainly inefficient
        def two_hex(value):
            return f"{value:02x}"

        return ":".join(map(two_hex, value))

    display_transformers = {
        "Ethernet.IP.src": ipaddress.ip_address,
        "Ethernet.IP.dst": ipaddress.ip_address,
        "Ethernet.IP6.src": ipaddress.ip_address,
        "Ethernet.IP6.dst": ipaddress.ip_address,
        "Ethernet.src": print_mac_address,
        "Ethernet.dst": print_mac_address,
    }

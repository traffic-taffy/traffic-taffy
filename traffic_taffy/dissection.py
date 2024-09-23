"""A Dissection class stores the results of a PCAP enumeration."""

from __future__ import annotations
from collections import defaultdict, Counter
from typing import Any, Dict, ClassVar
from logging import debug, info, error, warning
from enum import Enum
import msgpack
import ipaddress
from typing import List
from copy import deepcopy
from pathlib import Path
from traffic_taffy import __VERSION__ as VERSION
from io import BytesIO
import pkgutil

# TODO(hardaker): fix to not use a global
# note that this is designed to load only once before forking
iana_data = None
if not iana_data:
    # try a local copy first
    if Path("traffic_taffy/iana/tables.msgpakx").exists():
        iana_data = msgpack.load(Path.open("traffic_taffy/iana/tables.msgpak", "rb"))
    else:
        content = pkgutil.get_data("traffic_taffy", "iana/tables.msgpak")
        if content:
            content = BytesIO(content)
            iana_data = msgpack.load(content)
        else:
            warning("failed to load IANA data tables -- no enum expansion available")


class PCAPDissectorLevel(Enum):
    """Enumeration of supported dissection levels."""

    COUNT_ONLY = 1
    THROUGH_IP = 2
    COMMON_LAYERS = 3
    DETAILED = 10


class Dissection:
    """Class to store the data from an enumerated pcap."""

    DISSECTION_KEY: str = "PCAP_DISSECTION_VERSION"
    DISSECTION_VERSION: int = 8

    TOTAL_COUNT: str = "__TOTAL__"
    TOTAL_SUBKEY: str = "packet"
    WIDTH_SUBKEY: str = "__WIDTH__"
    NEW_RIGHT_SUBKEY: str = "__NEW_VALUES__"

    PRINTABLE_LENGTH: int = 40

    def __init__(
        self: Dissection,
        pcap_file: str,
        pcap_filter: str | None = None,
        maximum_count: int = 0,
        bin_size: int = 0,
        dissector_level: PCAPDissectorLevel = PCAPDissectorLevel.DETAILED,
        cache_file_suffix: str = "taffy",
        ignore_list: list | None = None,
        *_args: list,
        **_kwargs: dict,
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
        self.ignore_list = ignore_list or []
        self.iana_data = defaultdict(dict)

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
        """Timestamp currently being worked on."""
        return self._timestamp

    @timestamp.setter
    def timestamp(self: Dissection, newval: int) -> None:
        self._timestamp = newval

    @property
    def data(self: Dissection) -> dict:
        """The raw data in this dissection."""
        return self._data

    @data.setter
    def data(self: Dissection, newval: dict) -> None:
        self._data = newval

    @property
    def pcap_file(self: Dissection) -> str:
        """The PCAP file name of this dissection."""
        return self._pcap_file

    @pcap_file.setter
    def pcap_file(self: Dissection, newval: str) -> None:
        self._pcap_file = newval

    def incr(self: Dissection, key: str, value: Any, count: int = 1) -> None:
        """Increase one field within the counter."""
        # always save a total count at the zero bin
        # note: there should be no recorded tcpdump files from 1970 Jan 01 :-)
        self.data[0][key][value] += count
        if self.timestamp:
            self.data[self.timestamp][key][value] += count

    def calculate_metadata(self: Dissection) -> None:
        """Calculate thing like the number of value entries within each key/subkey."""
        # TODO(hardaker): do we do this with or without key and value matches?
        for timestamp in self.data:
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

    def merge(self: Dissection, other_dissection: Dissection) -> None:
        """Merge counters from another dissection into self."""
        for timestamp in other_dissection.data:
            for key in other_dissection.data[timestamp]:
                for subkey in other_dissection.data[timestamp][key]:
                    self.data[timestamp][key][subkey] += other_dissection.data[
                        timestamp
                    ][key][subkey]

    def merge_all(self: Dissection, other_dissections: List[Dissection]) -> None:
        """Merge multiple dissection contents into this one."""
        for dissection in other_dissections:
            self.merge(dissection)

    @staticmethod
    def subdict_producer() -> defaultdict:
        """Create a factory for creating a producer."""
        return defaultdict(Counter)

    #
    # Loading / Saving
    #

    def load_from_cache(
        self: Dissection, force_overwrite: bool = False, force_load: bool = True
    ) -> dict | None:
        """Load the dissection data from a cache."""
        if not self.pcap_file or not isinstance(self.pcap_file, str):
            return None
        if not Path(self.pcap_file + self.cache_file_suffix).exists():
            return None

        cached_file = self.pcap_file + self.cache_file_suffix
        cached_contents = self.load_saved(
            cached_file, dont_overwrite=True, force_load=force_load
        )

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

                if (
                    parameter == "pcap_file"
                    and Path(specified).name == Path(cached).name
                ):
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
        msg = "INCOMPATIBLE CACHE: remove the cache or don't use it to continue"
        raise ValueError(msg)

    def save_to_cache(self: Dissection, where: str | None = None) -> None:
        """Save the dissection contents to a cache."""
        if not where and self.pcap_file and isinstance(self.pcap_file, str):
            where = self.pcap_file + self.cache_file_suffix
        if where:
            self.save(where)

    def save(self: Dissection, where: str) -> None:
        """Save a generated dissection to a msgpack file."""
        # wrap the report in a version header
        versioned_cache = {
            self.DISSECTION_KEY: self.DISSECTION_VERSION,
            "file": self.pcap_file,
            "parameters": {},
            "dissection": self.data,
            "created_by": "traffic-taffy " + VERSION,
        }

        for parameter in self.parameters:
            versioned_cache["parameters"][parameter] = getattr(self, parameter)
            # TODO(hardaker): fix this hack

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

        # convert int keys that are too large
        for timestamp in versioned_cache["dissection"]:
            for key in versioned_cache["dissection"][timestamp]:
                versioned_cache["dissection"][timestamp][key] = dict(
                    versioned_cache["dissection"][timestamp][key]
                )
                # sigh -- msgpack can't handle large int based dictionary keys
                fix_list = []
                for subkey in versioned_cache["dissection"][timestamp][key]:
                    if isinstance(subkey, int) and subkey > 2**32 - 1:
                        debug(f"converting too large int key {key} {subkey}")
                        fix_list.append(subkey)

                for subkey in fix_list:
                    versioned_cache["dissection"][timestamp][key][
                        str(subkey)
                    ] = versioned_cache["dissection"][timestamp][key][subkey]
                    del versioned_cache["dissection"][timestamp][key][subkey]

        with Path(where).open("wb") as saveto:
            msgpack.dump(versioned_cache, saveto)

    def load_saved_contents(self: Dissection, versioned_cache: dict) -> None:
        """Set parameters from the cache."""
        # set the local parameters from the cache
        for parameter in self.parameters:
            setattr(self, parameter, versioned_cache["parameters"][parameter])

        # load the data
        self.data = versioned_cache["dissection"]

    def load_saved(
        self: Dissection,
        where: str,
        dont_overwrite: bool = False,
        force_load: bool = False,
    ) -> dict:
        """Load a saved report from a cache file."""
        with Path(where).open("rb") as cache_file:
            contents = msgpack.load(cache_file, strict_map_key=False)

        # convert the ignore list to a set (msgpack doesn't do sets)
        contents["parameters"]["ignore_list"] = set(
            contents["parameters"]["ignore_list"]
        )

        # check that the version header matches something we understand
        if not force_load and contents[self.DISSECTION_KEY] != self.DISSECTION_VERSION:
            raise ValueError(
                "improper saved dissection version: report version = "
                + str(contents[self.DISSECTION_KEY])
                + ", our version: "
                + str(self.DISSECTION_VERSION)
            )

        if not dont_overwrite:
            self.load_saved_contents(contents)

        return contents

    def filter(
        self: Dissection,
        timestamps: List[int] | None = None,
        match_string: str | None = None,
        match_value: str | None = None,
        minimum_count: int | None = None,
        make_printable: bool = False,
        match_expression: str | None = None,
    ) -> None:
        """Creates a new dissection that has been filtered based on passed criteria."""
        debug(
            f"filtering dissection with: {timestamps=}, {match_string=} {match_value=}, {minimum_count=}, {make_printable=}"
        )
        new_dissection: Dissection = Dissection(
            self.pcap_file,
            self.pcap_filter,
            self.maximum_count,
            self.bin_size,
            self.dissector_level,
            self.cache_file_suffix,
            self.ignore_list,
        )

        for timestamp, key, subkey, value in self.find_data(
            timestamps=timestamps,
            match_string=match_string,
            match_value=match_value,
            minimum_count=minimum_count,
            make_printable=make_printable,
            match_expression=match_expression,
        ):
            new_dissection.data[timestamp][key][subkey] = value

        debug("  done filtering")
        return new_dissection

    def find_data(
        self: Dissection,
        timestamps: List[int] | None = None,
        match_string: str | None = None,
        match_value: str | None = None,
        minimum_count: int | None = None,
        make_printable: bool = False,
        match_expression: str | None = None,
    ) -> list:
        """Search through data for appropriate records."""
        data = self.data
        if match_value and not isinstance(match_value, list):
            match_value = [match_value]

        if not timestamps:
            timestamps = data.keys()

        match_eval_compiled = None
        if match_expression:
            match_eval_compiled = compile(f"{match_expression}", "<string>", "eval")
        # find timestamps/key values with at least one item above count
        # TODO(hardaker): we should really use pandas for this
        usable = defaultdict(set)
        for timestamp in timestamps:
            for key in data[timestamp]:
                # if they requested a match string
                if match_string and match_string not in key:
                    continue

                # ensure at least one of the count valuse for the
                # stream gets above minimum_count
                for subkey, count in data[timestamp][key].items():
                    if not minimum_count or (
                        minimum_count and abs(count) >= minimum_count
                    ):
                        usable[key].add(subkey)

        # TODO(hardaker): move the timestamp inside the other fors for faster
        # processing of skipped key/subkeys
        globals = {}  # TODO(hardaker): maybe create some in the future

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

                    subkey_original = subkey
                    if make_printable:
                        subkey = Dissection.make_printable(key, subkey)
                        count = Dissection.make_printable(None, count)

                    if match_value and not any(x in subkey for x in match_value):
                        continue

                    if match_eval_compiled:
                        result = eval(
                            match_eval_compiled,
                            globals,
                            {
                                "timestamp": timestamp,
                                "key": key,
                                "subkey": subkey,
                                "value": data[timestamp][key][subkey_original],
                            },
                        )

                        # if the evaluation didn't return truthy,
                        # ignore this entry
                        if not result:
                            continue

                    yield (timestamp, key, subkey, count)

    @staticmethod
    def make_printable(value_type: str, value: Any) -> str:
        """Turn a value into a printable version if needed."""
        try:
            if isinstance(value, bytes):
                if value_type in Dissection.DISPLAY_TRANSFORMERS:
                    value = str(
                        Dissection.DISPLAY_TRANSFORMERS[value_type](value_type, value)
                    )
                else:
                    value = "0x" + value.hex()
            elif value_type in Dissection.ENUM_TRANSLATORS:
                value = str(Dissection.ENUM_TRANSLATORS[value_type](value_type, value))
            else:
                value = str(value)
        except Exception:
            if isinstance(value, bytes):
                value = "0x" + value.hex()
            else:
                value = "[unprintable]"
        if len(value) > Dissection.PRINTABLE_LENGTH:
            # truncate to reasonable
            value = value[0 : Dissection.PRINTABLE_LENGTH] + "..."
        return value

    @staticmethod
    def print_mac_address(value_type: str, value: bytes) -> str:
        """Convert bytes to ethernet mac style address."""

        # TODO(hardaker): certainly inefficient
        def two_hex(value: bytes) -> str:
            return f"{value:02x}"

        return ":".join(map(two_hex, value))

    @staticmethod
    def print_ip_address(value_type: str, value: bytes) -> str:
        """Convert binary bytes to IP addresses (v4 and v6)."""
        return ipaddress.ip_address(value)

    UDP_PORTS: ClassVar[Dict[str, str]] = {
        "53": "DNS",
    }

    IANA_TRANSLATORS: ClassVar[Dict[str, str]] = {
        "Ethernet_IP_proto": "protocols",
        "Ethernet_IPv6_proto": "protocols",
        "Ethernet_IP_UDP_sport": "udp_ports",
        "Ethernet_IP_UDP_dport": "udp_ports",
        "Ethernet_IP_TCP_sport": "tcp_ports",
        "Ethernet_IP_TCP_dport": "tcp_ports",
        "Ethernet_IPv6_UDP_sport": "udp_ports",
        "Ethernet_IPv6_UDP_dport": "udp_ports",
        "Ethernet_IPv6_TCP_sport": "tcp_ports",
        "Ethernet_IPv6_TCP_dport": "tcp_ports",
        "Ethernet_IP_ICMP_code": "icmp_codes",
        "Ethernet_IP_ICMP_type": "icmp_types",
        "Ethernet_IP_ICMP_IP in ICMP_UDP in ICMP_dport": "udp_ports",
        "Ethernet_IP_ICMP_IP in ICMP_UDP in ICMP_sport": "udp_ports",
        "Ethernet_IP_ICMP_IP in ICMP_TCP in ICMP_dport": "tcp_ports",
        "Ethernet_IP_ICMP_IP in ICMP_TCP in ICMP_sport": "tcp_ports",
        "Ethernet_IP_ICMP_IP in ICMP_protoc": "protocols",
        "Ethernet_IP_UDP_DNS_qd_qclass": "dns_classes",
        "Ethernet_IP_UDP_DNS_ns_rclass": "dns_classes",
        "Ethernet_IP_UDP_DNS_an_rclass": "dns_classes",
        "Ethernet_IP_UDP_DNS_qd_qtype": "dns_rrtypes",
        "Ethernet_IP_UDP_DNS_ns_type": "dns_rrtypes",
        "Ethernet_IP_UDP_DNS_an_type": "dns_rrtypes",
        "Ethernet_IP_UDP_DNS_opcode": "dns_opcodes",
        "Ethernet_IP_TCP_DNS_qd_qclass": "dns_classes",
        "Ethernet_IP_TCP_DNS_ns_rclass": "dns_classes",
        "Ethernet_IP_TCP_DNS_an_rclass": "dns_classes",
        "Ethernet_IP_TCP_DNS_qd_qtype": "dns_rrtypes",
        "Ethernet_IP_TCP_DNS_ns_type": "dns_rrtypes",
        "Ethernet_IP_TCP_DNS_an_type": "dns_rrtypes",
        "Ethernet_IP_TCP_DNS_opcode": "dns_opcodes",
    }

    @staticmethod
    def print_iana_values(value_type: str, value: bytes) -> str:
        """Use IANA lookup tables for converting protocol enumerations to human readable types."""
        table_name = Dissection.IANA_TRANSLATORS.get(value_type)

        if not table_name:
            return value

        table = iana_data[table_name]
        value = str(value)
        if value not in table:
            return value

        return f"{value} ({table[value]})"

    ENUM_TRANSLATORS: ClassVar[Dict[str, callable]] = {
        "Ethernet_IP_proto": print_iana_values,
        "Ethernet_IPv6_proto": print_iana_values,
        "Ethernet_IP_UDP_sport": print_iana_values,
        "Ethernet_IP_UDP_dport": print_iana_values,
        "Ethernet_IP_TCP_sport": print_iana_values,
        "Ethernet_IP_TCP_dport": print_iana_values,
        "Ethernet_IP_ICMP_IP in ICMP_UDP in ICMP_dport": print_iana_values,
        "Ethernet_IP_ICMP_IP in ICMP_UDP in ICMP_sport": print_iana_values,
        "Ethernet_IP_ICMP_IP in ICMP_TCP in ICMP_dport": print_iana_values,
        "Ethernet_IP_ICMP_IP in ICMP_TCP in ICMP_sport": print_iana_values,
        "Ethernet_IP_ICMP_IP in ICMP_proto": print_iana_values,
        "Ethernet_IPv6_UDP_sport": print_iana_values,
        "Ethernet_IPv6_UDP_dport": print_iana_values,
        "Ethernet_IPv6_TCP_sport": print_iana_values,
        "Ethernet_IPv6_TCP_dport": print_iana_values,
        "Ethernet_IP_ICMP_code": print_iana_values,
        "Ethernet_IP_ICMP_type": print_iana_values,
        "Ethernet_IP_UDP_DNS_qd_qclass": print_iana_values,
        "Ethernet_IP_UDP_DNS_ns_rclass": print_iana_values,
        "Ethernet_IP_UDP_DNS_an_rclass": print_iana_values,
        "Ethernet_IP_UDP_DNS_qd_qtype": print_iana_values,
        "Ethernet_IP_UDP_DNS_ns_type": print_iana_values,
        "Ethernet_IP_UDP_DNS_an_type": print_iana_values,
        "Ethernet_IP_UDP_DNS_opcode": print_iana_values,
        "Ethernet_IP_TCP_DNS_qd_qclass": print_iana_values,
        "Ethernet_IP_TCP_DNS_ns_rclass": print_iana_values,
        "Ethernet_IP_TCP_DNS_an_rclass": print_iana_values,
        "Ethernet_IP_TCP_DNS_qd_qtype": print_iana_values,
        "Ethernet_IP_TCP_DNS_ns_type": print_iana_values,
        "Ethernet_IP_TCP_DNS_an_type": print_iana_values,
        "Ethernet_IP_TCP_DNS_opcode": print_iana_values,
    }

    # has to go at the end to pick up the above function names
    DISPLAY_TRANSFORMERS: ClassVar[Dict[str, callable]] = {
        "Ethernet_IP_src": print_ip_address,
        "Ethernet_IP_dst": print_ip_address,
        "Ethernet_IP6_src": print_ip_address,
        "Ethernet_IP6_dst": print_ip_address,
        "Ethernet_src": print_mac_address,
        "Ethernet_dst": print_mac_address,
    }

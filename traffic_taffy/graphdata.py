"""A module for storing/transforming data (frequently to be graphed)."""

import os
from pandas import DataFrame, to_datetime, concat
from traffic_taffy.dissection import Dissection


class PcapGraphData:
    """A base class for storing/transforming data (frequently to be graphed)."""

    def __init__(
        self,
        match_string: str = None,
        match_value: str = None,
        minimum_count: int = None,
        match_expression: str = None,
    ):
        """Create an instance of a PcapGraphData."""
        self.dissections = []
        self.match_string = match_string
        self.match_value = match_value
        self.minimum_count = minimum_count
        self.match_expression = match_expression

    @property
    def dissections(self) -> list:
        """Dissections stored within the PcapGraphData instance."""
        return self._dissections

    @dissections.setter
    def dissections(self, newvalue: list) -> None:
        self._dissections = newvalue

    def normalize_bins(self, dissection: Dissection, minimalize: bool = False) -> dict:
        """Transform a dissection's list of data into a dictionary."""
        results: dict = {}
        time_keys: list = list(dissection.data.keys())
        if time_keys[0] == 0:  # likely always
            time_keys.pop(0)

        results: dict = {"time": [], "count": [], "index": [], "key": [], "subkey": []}

        # TODO(hardaker): this could likely be made much more efficient and needs hole-filling
        for timestamp, key, subkey, value in dissection.find_data(
            timestamps=time_keys,
            match_string=self.match_string,
            match_value=self.match_value,
            minimum_count=self.minimum_count,
            make_printable=True,
            match_expression=self.match_expression,
        ):
            index = key + "=" + subkey
            results["count"].append(int(value))
            results["index"].append(index)
            results["key"].append(key)
            results["subkey"].append(subkey)
            results["time"].append(timestamp)

        return results

    def get_dataframe(
        self, merge: bool = False, calculate_load_fraction: bool = False
    ) -> DataFrame:
        """Create a pandas dataframe from stored dissections."""
        datasets = []
        if merge:
            dissection = next(self.dissections).clone()
            for tomerge in self.dissections:
                dissection.merge(tomerge)
            dissections = [dissection]
        else:
            dissections = self.dissections

        for dissection in dissections:
            data = self.normalize_bins(dissection)
            data = DataFrame.from_records(data)
            data["filename"] = os.path.basename(dissection.pcap_file)
            data["time"] = to_datetime(data["time"], unit="s", utc=True)
            data["key"] = data["index"]
            datasets.append(data)
        datasets = concat(datasets, ignore_index=True)

        if calculate_load_fraction:
            # TODO(hardaker): this only works with single key types
            # (need to further group by keys and the max of each key being graphed)
            time_groups = datasets.groupby(["time"])
            datasets["load_fraction"] = (
                100 * datasets["count"] / time_groups.transform("sum")["count"]
            )

        return datasets

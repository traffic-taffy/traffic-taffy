import os
from pandas import DataFrame, to_datetime, concat


class PcapGraphData:
    def __init__(self):
        self.dissections = []
        pass

    @property
    def dissections(self):
        return self._dissections

    @dissections.setter
    def dissections(self, newvalue):
        self._dissections = newvalue

    def normalize_bins(self, dissection):
        results = {}
        time_keys = list(dissection.data.keys())
        if time_keys[0] == 0:  # likely always
            time_keys.pop(0)

        results = {"time": [], "count": [], "index": [], "key": [], "subkey": []}

        # TODO: this could likely be made much more efficient and needs hole-filling
        for timestamp, key, subkey, value in dissection.find_data(
            timestamps=time_keys,
            match_string=self.match_string,
            match_value=self.match_value,
            minimum_count=self.minimum_count,
            make_printable=True,
        ):
            index = key + "=" + subkey
            results["count"].append(int(value))
            results["index"].append(index)
            results["key"].append(key)
            results["subkey"].append(subkey)
            results["time"].append(timestamp)

        return results

    def get_dataframe(self, merge=False, calculate_load_fraction=False):
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

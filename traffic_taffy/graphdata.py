import os
from traffic_taffy.dissector import PCAPDissector
from pandas import DataFrame, to_datetime, concat


class PcapGraphData:
    def __init__(self):
        pass

    @property
    def dissections(self):
        return self._dissections

    @dissections.setter
    def dissection(self, newvalue):
        self._dissections = newvalue

    def normalize_bins(self, counters):
        results = {}
        time_keys = list(counters.keys())
        if time_keys[0] == 0:  # likely always
            time_keys.pop(0)

        results = {"time": [], "count": [], "index": [], "key": []}

        # TODO: this could likely be made much more efficient and needs hole-filling
        for timestamp, key, subkey, value in PCAPDissector.find_data(
            counters,
            timestamps=time_keys,
            match_string=self.match_key,
            match_value=self.match_value,
            minimum_count=self.minimum_count,
            make_printable=True,
        ):
            index = key + "=" + subkey
            results["count"].append(int(value))
            results["index"].append(index)
            results["key"].append(index)
            results["time"].append(timestamp)

        return results

    def merge_datasets(self):
        datasets = []
        for filename, dissection in self.dissections.items():
            data = self.normalize_bins(dissection.data)
            data = DataFrame.from_records(data)
            data["filename"] = os.path.basename(filename)
            data["time"] = to_datetime(data["time"], unit="s")
            data["key"] = data["index"]
            datasets.append(data)
        datasets = concat(datasets, ignore_index=True)
        return datasets

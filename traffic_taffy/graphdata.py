import os
from traffic_taffy.dissector import PCAPDissector
from pandas import DataFrame, to_datetime, concat


class PcapGraphData:
    def __init__(self):
        pass

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, newvalue):
        self._data = newvalue

    def normalize_bins(self, counters):
        results = {}
        time_keys = list(counters.keys())
        if time_keys[0] == 0:  # likely always
            time_keys.pop(0)
        time_keys[0]
        time_keys[-1]

        results = {"time": [], "count": [], "index": []}

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
            results["time"].append(timestamp)

        return results

    def merge_datasets(self):
        datasets = []
        for dataset in self.data:
            data = self.normalize_bins(self.data[dataset])
            data = DataFrame.from_records(data)
            data["filename"] = os.path.basename(dataset)
            data["time"] = to_datetime(data["time"], unit="s")
            datasets.append(data)
        datasets = concat(datasets)
        return datasets

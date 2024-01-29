from logging import debug, error
from typing import List
import datetime as dt
from datetime import datetime

from traffic_taffy.comparison import Comparison
from traffic_taffy.dissectmany import PCAPDissectMany
from traffic_taffy.dissector import PCAPDissectorLevel
from traffic_taffy.dissection import Dissection


class PcapCompare:
    "Takes a set of PCAPs to then perform various comparisons upon"

    REPORT_VERSION: int = 2

    def __init__(
        self,
        pcap_files: List[str],
        maximum_count: int = 0,  # where 0 == all
        deep: bool = True,
        pcap_filter: str | None = None,
        cache_results: bool = False,
        cache_file_suffix: str = "taffy",
        bin_size: int | None = None,
        dissection_level: PCAPDissectorLevel = PCAPDissectorLevel.COUNT_ONLY,
        between_times: List[int] | None = None,
        ignore_list: List[str] = [],
        layers: List[str] | None = None,
    ) -> None:
        self.pcap_files = pcap_files
        self.deep = deep
        self.maximum_count = maximum_count
        self.pcap_filter = pcap_filter
        self.cache_results = cache_results
        self.dissection_level = dissection_level
        self.between_times = between_times
        self.bin_size = bin_size
        self.cache_file_suffix = cache_file_suffix
        self.ignore_list = ignore_list
        self.layers = layers

    @property
    def pcap_files(self):
        return self._pcap_files

    @pcap_files.setter
    def pcap_files(self, new_pcap_files):
        self._pcap_files = new_pcap_files

    @property
    def reports(self):
        return self._reports

    @reports.setter
    def reports(self, newvalue):
        self._reports = newvalue

    def compare_dissections(self, left_side: dict, right_side: dict) -> dict:
        "compares the results from two reports"

        report = {}

        keys = set(left_side.keys())
        keys = keys.union(right_side.keys())
        for key in keys:
            report[key] = {}

            if key not in left_side:
                left_side[key] = {}
            left_side_total = sum(left_side[key].values())

            if key not in right_side:
                right_side[key] = {}
            right_side_total = sum(right_side[key].values())

            new_left_count = 0
            for subkey in left_side[key].keys():
                delta_percentage = 0.0
                total = 0
                if subkey in right_side[key]:
                    left_percentage = left_side[key][subkey] / left_side_total
                    right_percentage = right_side[key][subkey] / right_side_total
                    delta_percentage = right_percentage - left_percentage
                    total = right_side[key][subkey] + left_side[key][subkey]
                    left_count = left_side[key][subkey]
                    right_count = right_side[key][subkey]
                else:
                    delta_percentage = -1.0
                    left_percentage = left_side[key][subkey] / left_side_total
                    right_percentage = 0.0
                    total = -left_side[key][subkey]
                    left_count = left_side[key][subkey]
                    right_count = 0
                    new_left_count += 1

                delta_absolute = right_count - left_count
                report[key][subkey] = {
                    "delta_percentage": delta_percentage,
                    "delta_absolute": delta_absolute,
                    "total": total,
                    "left_count": left_count,
                    "right_count": right_count,
                    "left_percentage": left_percentage,
                    "right_percentage": right_percentage,
                }

            new_right_count = 0
            for subkey in right_side[key].keys():
                if subkey not in report[key]:
                    delta_percentage = 1.0
                    total = right_side[key][subkey]
                    left_count = 0
                    right_count = right_side[key][subkey]
                    left_percentage = 0.0
                    right_percentage = right_side[key][subkey] / right_side_total
                    new_right_count += 1  # this value wasn't in the left

                    report[key][subkey] = {
                        "delta_percentage": delta_percentage,
                        "delta_absolute": right_count,
                        "total": total,
                        "left_count": left_count,
                        "right_count": right_count,
                        "left_percentage": left_percentage,
                        "right_percentage": right_percentage,
                    }

            if right_side_total == 0:
                right_percent = 100
            else:
                right_percent = new_right_count / right_side_total

            if left_side_total == 0:
                left_percent = 100
            else:
                left_percent = new_left_count / left_side_total

            report[key][Dissection.NEW_RIGHT_SUBKEY] = {
                "delta_absolute": new_right_count - new_left_count,
                "total": new_left_count + new_right_count,
                "left_count": new_left_count,
                "right_count": new_right_count,
                "left_percentage": left_percent,
                "right_percentage": right_percent,
                "delta_percentage": right_percent - left_percent,
            }

        return Comparison(report)

    def load_pcaps(self) -> None:
        # load the first as a reference pcap
        pdm = PCAPDissectMany(
            self.pcap_files,
            bin_size=self.bin_size,
            maximum_count=self.maximum_count,
            pcap_filter=self.pcap_filter,
            cache_results=self.cache_results,
            cache_file_suffix=self.cache_file_suffix,
            dissector_level=self.dissection_level,
            ignore_list=self.ignore_list,
            layers=self.layers,
        )
        results = pdm.load_all()
        return results

    def compare(self) -> List[Comparison]:
        "Compares each pcap against the original source"

        dissections = self.load_pcaps()
        self.compare_all(dissections)
        return self.reports

    def compare_all(self, dissections) -> List[Comparison]:
        reports = []
        if len(self.pcap_files) > 1:
            # multiple file comparison
            reference = next(dissections)
            for other in dissections:
                # compare the two global summaries

                report = self.compare_dissections(reference.data[0], other.data[0])
                report.title = f"{reference.pcap_file} vs {other.pcap_file}"

                reports.append(report)
        else:
            # deal with timestamps within a single file
            reference = list(dissections)[0].data
            timestamps = list(reference.keys())
            if len(timestamps) <= 2:  # just 0-summary plus a single stamp
                error(
                    "the requested pcap data was not long enough to compare against itself"
                )
                raise ValueError(
                    "not enough of a single capture file to time-bin the results"
                )
            debug(
                f"found {len(timestamps)} timestamps from {timestamps[2]} to {timestamps[-1]}"
            )

            for timestamp in range(
                2, len(timestamps)
            ):  # second real non-zero timestamp to last
                time_left = timestamps[timestamp - 1]
                time_right = timestamps[timestamp]

                # see if we were asked to only use particular time ranges
                if self.between_times and (
                    time_left < self.between_times[0]
                    or time_right > self.between_times[1]
                ):
                    # debug(f"skipping timestamps {time_left} and {time_right}")
                    continue

                debug(f"comparing timestamps {time_left} and {time_right}")

                report = self.compare_dissections(
                    reference[time_left],
                    reference[time_right],
                )

                title_left = datetime.fromtimestamp(time_left, dt.UTC).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                title_right = datetime.fromtimestamp(time_right, dt.UTC).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )

                report.title = f"time {title_left} vs time {title_right}"
                reports.append(report)

                continue

                # takes way too much memory to do it "right"
                # reports.append(
                #     {
                #         "report": report,
                #         "title": f"time {time_left} vs time {time_right}",
                #     }
                # )

        self.reports = reports
        return reports


def compare_add_parseargs(compare_parser, add_subgroup: bool = True):
    if add_subgroup:
        compare_parser = compare_parser.add_argument_group("Comparison result options")

    compare_parser.add_argument(
        "-t",
        "--print-threshold",
        default=0.0,
        type=float,
        help="Don't print results with abs(percent) less than this threshold",
    )

    compare_parser.add_argument(
        "-P", "--only-positive", action="store_true", help="Only show positive entries"
    )

    compare_parser.add_argument(
        "-N", "--only-negative", action="store_true", help="Only show negative entries"
    )

    compare_parser.add_argument(
        "-x",
        "--top-records",
        default=None,
        type=int,
        help="Show the top N records from each section.",
    )

    compare_parser.add_argument(
        "-r",
        "--reverse_sort",
        action="store_true",
        help="Reverse the sort order of reports",
    )

    compare_parser.add_argument(
        "-T",
        "--between-times",
        nargs=2,
        type=int,
        help="For single files, only display results between these timestamps",
    )

    return compare_parser


def get_comparison_args(args):
    return {
        "maximum_count": args.packet_count or 0,
        "print_threshold": float(args.print_threshold) / 100.0,
        "minimum_count": args.minimum_count,
        "match_string": args.match_string,
        "only_positive": args.only_positive,
        "only_negative": args.only_negative,
        "top_records": args.top_records,
        "reverse_sort": args.reverse_sort,
        "sort_by": args.sort_by,
    }

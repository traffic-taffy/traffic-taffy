"""A module for dissecting a number of PCAP files."""

from __future__ import annotations
from io import BufferedIOBase
from concurrent.futures import ProcessPoolExecutor
from logging import info
import copy
import multiprocessing
from pcap_parallel import PCAPParallel
from typing import List

from traffic_taffy.dissector import PCAPDissector
from traffic_taffy.dissection import Dissection


class PCAPDissectMany:
    """A class for dissecting a number of PCAP files."""

    def __init__(self, pcap_files: List[str], *args: list, **kwargs: dict):
        """Create a PCAPDissectMany instance."""
        self.pcap_files = pcap_files
        self.args = args
        self.kwargs = kwargs
        self.futures = {}

        self.maximum_cores = self.kwargs.get("maximum_cores")
        if not self.maximum_cores:
            # since we're loading multiple files in parallel, reduce the
            # maximum number of cores available to the splitter
            # Note: this may undercount due to int flooring()
            self.maximum_cores = int(multiprocessing.cpu_count() / len(self.pcap_files))

    def load_pcap_piece(self, pcap_io_buffer: BufferedIOBase) -> Dissection:
        """Load one piece of a pcap from a buffer."""
        kwargs = copy.copy(self.kwargs)
        # force false for actually loading
        kwargs["cache_results"] = False

        pd = PCAPDissector(
            pcap_io_buffer,
            *self.args,
            **self.kwargs,
        )
        pd.load()
        pd.dissection.pcap_file = "bogus"
        return pd.dissection

    def load_pcap(
        self,
        pcap_file: str,
        split_size: int | None = None,
    ) -> Dissection:
        """Load one pcap file."""
        pd = PCAPDissector(
            pcap_file,
            *self.args,
            **self.kwargs,
        )
        dissection = pd.load_from_cache(
            force_overwrite=self.kwargs.get("force_overwrite", False),
            force_load=self.kwargs.get("force_load", False),
        )
        if dissection:
            return dissection

        info(f"processing {pcap_file}")
        ps = PCAPParallel(
            pcap_file,
            split_size=split_size,
            callback=self.load_pcap_piece,
            maximum_count=self.kwargs.get("maximum_count", 0),
            maximum_cores=self.maximum_cores,
        )
        results = ps.split()

        # the data is coming back in (likely overlapping) chunks, and
        # we need to merge them together
        dissection = results.pop(0).result()
        dissection.pcap_file = pcap_file  # splitting has the wrong name
        for result in results:
            dissection.merge(result.result())

        dissection.calculate_metadata()

        if self.kwargs.get("cache_results"):
            # create a dissector just to save the cache
            # (we don't call load())
            dissection.pcap_file = pcap_file
            dissection.save_to_cache(
                pcap_file + "." + self.kwargs.get("cache_file_suffix", "taffy")
            )

        return dissection

    def load_all(
        self, return_as_list: bool = False, dont_fork: bool = False
    ) -> List[Dissection]:
        """Load all PCAPs in parallel."""
        if dont_fork:
            # handle each one individually -- typically for inserting debugging stops
            dissections = []
            for pcap_file in self.pcap_files:
                dissection = self.load_pcap(pcap_file)
                dissections.append(dissection)
            return dissections

        # use all available resources
        with ProcessPoolExecutor() as executor:
            dissections = executor.map(self.load_pcap, self.pcap_files)
            if return_as_list:  # convert from generator
                dissections = list(dissections)
            return dissections

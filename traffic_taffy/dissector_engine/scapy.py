"""A scapy engine for deeply parsing and counting packets."""

from __future__ import annotations
from traffic_taffy.dissector_engine import DissectionEngine
from pcap_parallel import PCAPParallel
from logging import warning

from scapy.all import sniff, load_layer
from tempfile import NamedTemporaryFile
from traffic_taffy.taffy_config import TaffyConfig, taffy_default


taffy_default("dissect.engines.scapy.use_temp_files", False)
taffy_default("dissect.engines.scapy.temp_file_directory", None)


class DissectionEngineScapy(DissectionEngine):
    """A scapy engine class for deeply parsing and counting packets."""

    def __init__(self, *args: list, **kwargs: dict):
        """Create a scapy engine class."""
        super().__init__(*args, **kwargs)

        self.taffy_config = TaffyConfig()

    def load_data(self) -> None:
        """Load a pcap file into a nested dictionary of statistical counts."""
        if isinstance(self.pcap_file, str):
            load_this = PCAPParallel.open_maybe_compressed(self.pcap_file)
        else:
            load_this = self.pcap_file

        use_temp_files: bool = self.taffy_config.get_dotnest(
            "dissect.engines.scapy.use_temp_files"
        )
        if self.pcap_filter is not None and self.pcap_filter != "":
            # somehow scapy hangs when a filter is applied to a memory object
            use_temp_files = True

        if self.layers:
            for layer in self.layers:
                load_layer(layer)

        if use_temp_files:
            tmp_directory = self.taffy_config.get_dotnest(
                "dissect.engines.scapy.temp_file_directory"
            )
            with NamedTemporaryFile(dir=tmp_directory) as tmpf:
                tmpf.write(load_this.read())
                tmpf.flush()

                sniff(
                    offline=tmpf.name,
                    prn=self.callback,
                    store=0,
                    count=self.maximum_count,
                    filter=self.pcap_filter,
                )

        else:
            sniff(
                offline=load_this,
                prn=self.callback,
                store=0,
                count=self.maximum_count,
                filter=self.pcap_filter,
            )

            # TODO(hardaker): for some reason this fails on xz compressed files when processing in parallel

    def add_item(self, field_value: str | int, prefix: str) -> None:
        """Add an item to the self.dissection regardless of it's various types"""
        if isinstance(field_value, list):
            if len(field_value) > 0:
                # if it's a list of tuples, count the (eg TCP option) names
                #
                # TODO(hardaker): values can be always the same or things like timestamps
                #       that will always change or are too unique
                if isinstance(field_value[0], tuple):
                    for item in field_value:
                        self.incr(prefix, item[0])
                else:
                    for item in field_value:
                        self.add_item(item, prefix)
            # else:
            #     debug(f"ignoring empty-list: {field_value}")
        elif isinstance(field_value, (str, int, float)):
            self.incr(prefix, field_value)

        elif isinstance(field_value, bytes):
            try:
                converted = field_value.decode("utf-8")
                self.incr(prefix, converted)
            except Exception:
                converted = "0x" + field_value.hex()
                self.incr(prefix, converted)

    def add_layer(self, layer, prefix: str | None = "") -> None:
        """Analyze a layer to add counts to each layer sub-component."""
        if hasattr(layer, "fields_desc"):
            name_list = [field.name for field in layer.fields_desc]
        elif hasattr(layer, "fields"):
            name_list = [field.name for field in layer.fields]
        else:
            warning(f"unavailable to deep dive into: {layer}")
            return

        for field_name in name_list:
            new_prefix = prefix + field_name

            if new_prefix in self.ignore_list:
                continue

            try:
                field_value = getattr(layer, field_name)
                if not field_value:  ## can return empty field values like []
                    continue
                if hasattr(field_value, "fields"):
                    self.add_layer(field_value, new_prefix + "_")
                else:
                    self.add_item(field_value, new_prefix)
            except Exception as e:
                warning(f"scapy error at '{prefix}' in field '{field_name}'")
                warning(e)

    def callback(self, packet) -> None:
        """Handle one packet to dissect."""
        prefix = "_"
        self.start_packet(int(packet.time))

        for payload in packet.iterpayloads():
            prefix = f"{prefix}{payload.name}_"
            self.add_layer(payload, prefix[1:])

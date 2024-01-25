from traffic_taffy.dissector_engine import DissectionEngine
from traffic_taffy.dissection import Dissection
from pcap_parallel import PCAPParallel as pcapp
from logging import warning

from scapy.all import sniff, load_layer


class DissectionEngineScapy(DissectionEngine):
    def _init_(self, *args, **kwargs):
        super()._init_(*args, **kwargs)

    def load(self) -> Dissection:
        "Loads a pcap file into a nested dictionary of statistical counts"
        self.init_dissection()
        load_this = self.pcap_file
        if isinstance(self.pcap_file, str):
            load_this = pcapp.open_maybe_compressed(self.pcap_file)

        if self.layers:
            for layer in self.layers:
                load_layer(layer)

        sniff(
            offline=load_this,
            prn=self.callback,
            store=0,
            count=self.maximum_count,
            filter=self.pcap_filter,
        )
        self.dissection.calculate_metadata()
        # TODO: for some reason this fails on xz compressed files when processing in parallel
        return self.dissection

    def add_item(self, field_value, prefix: str) -> None:
        "Adds an item to the self.dissection regardless of it's various types"

        if isinstance(field_value, list):
            if len(field_value) > 0:
                # if it's a list of tuples, count the (eg TCP option) names
                # TODO: values can be always the same or things like timestamps
                #       that will always change or are too unique
                if isinstance(field_value[0], tuple):
                    for item in field_value:
                        self.dissection.incr(prefix, item[0])
                else:
                    for item in field_value:
                        self.add_item(item, prefix)
            # else:
            #     debug(f"ignoring empty-list: {field_value}")
        elif (
            isinstance(field_value, str)
            or isinstance(field_value, int)
            or isinstance(field_value, float)
        ):
            self.dissection.incr(prefix, field_value)

        elif isinstance(field_value, bytes):
            try:
                converted = field_value.decode("utf-8")
                self.dissection.incr(prefix, converted)
            except Exception:
                converted = "0x" + field_value.hex()
                self.dissection.incr(prefix, converted)

    def add_layer(self, layer, prefix: str | None = "") -> None:
        "Analyzes a layer to add counts to each layer sub-component"

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
                if hasattr(field_value, "fields"):
                    self.add_layer(field_value, new_prefix + ".")
                else:
                    self.add_item(field_value, new_prefix)
            except Exception as e:
                warning(f"scapy error at '{prefix}' in field '{field_name}'")
                warning(e)

    def callback(self, packet):
        prefix = "."
        self.timestamp = int(packet.time)
        if self.bin_size:
            self.timestamp = self.timestamp - self.timestamp % self.bin_size

        self.dissection.timestamp = int(self.timestamp)
        self.dissection.incr(Dissection.TOTAL_COUNT, Dissection.TOTAL_SUBKEY)
        for payload in packet.iterpayloads():
            prefix = f"{prefix}{payload.name}."
            self.add_layer(payload, prefix[1:])

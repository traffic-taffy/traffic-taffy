from pathlib import Path
from logging import error, info, debug
import ip2asn

from traffic_taffy.hooks import register_hook
from traffic_taffy.dissector import POST_DISSECT_HOOK, INIT_HOOK
from traffic_taffy.dissection import Dissection
from traffic_taffy.taffy_config import taffy_default, TaffyConfig

i2a = None

taffy_default("modules.ip2asn.database", "ip2asn-combined.tsv")


@register_hook(INIT_HOOK)
def init_ip2asn(**kwargs):
    global i2a

    if i2a is None:
        config = TaffyConfig()
        db_path = config.get_dotnest("modules.ip2asn.database")

        if not Path(db_path).exists():
            error("The ip2asn plugin requires a ip2asn-combined.tsv in this directory")
            error("Please download it from https://iptoasn.com/")

        info(f"loading {db_path}")
        i2a = ip2asn.IP2ASN(db_path)
        info("  ... loaded")


@register_hook(POST_DISSECT_HOOK)
def ip_to_asn(dissection: Dissection, **kwargs):
    init_ip2asn()

    timestamps = dissection.data.keys()

    for timestamp in timestamps:
        keys = list(dissection.data[timestamp].keys())

        for key in keys:
            key = str(key)
            if (
                key.endswith("IP_src")
                or key.endswith("IP_dst")
                or key.endswith("IPv6_src")
                or key.endswith("IPv6_dst")
            ):
                for value in dissection.data[timestamp][key]:
                    count = dissection.data[timestamp][key][value]
                    details = None

                    # TODO(hardaker): doesn't handle bytes addresses from dpkt
                    try:
                        details = i2a.lookup_address(value)
                    except Exception:
                        debug(f"failed to parse address: {value}")
                    if not details:
                        continue

                    dissection.data[timestamp][key + "_ASN"][details["ASN"]] += count
                    dissection.data[timestamp][key + "_country"][
                        details["country"]
                    ] += count
                    dissection.data[timestamp][key + "_owner"][
                        details["owner"]
                    ] += count

from pathlib import Path
from logging import error, info, debug
import ip2asn

from traffic_taffy.hooks import register_hook
from traffic_taffy.dissector import POST_DISSECT_HOOK
from traffic_taffy.dissection import Dissection

if not Path("ip2asn-combined.tsv").exists():
    error("The ip2asn plugin requires a ip2asn-combined.tsv in this directory")
    error("Please download it from https://iptoasn.com/")

info("loading ip2asn-combined.tsv")
i2a = ip2asn.IP2ASN("ip2asn-combined.tsv")
info("  ... loaded")


@register_hook(POST_DISSECT_HOOK)
def ip_to_asn(dissection: Dissection, **kwargs):
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

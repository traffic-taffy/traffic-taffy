"""A traffic taffy module to split the last five labels and count them"""
from traffic_taffy.hooks import register_hook
from traffic_taffy.dissector import POST_DISSECT_HOOK
from traffic_taffy.dissection import Dissection

import dnssplitter

splitter = dnssplitter.DNSSplitter()
splitter.init_tree()


@register_hook(POST_DISSECT_HOOK)
def split_dns_names(dissection: Dissection, **kwargs):
    """Split a DNS name into pieces and count the last 5 labels"""
    timestamps = dissection.data.keys()

    for timestamp in timestamps:
        keys = list(dissection.data[timestamp].keys())

        for key in keys:
            key = str(key)
            if (
                key.endswith("_qname")
                or key.endswith("_mname")
                or key.endswith("_rrname")
            ):
                for value in dissection.data[timestamp][key]:
                    count = dissection.data[timestamp][key][value]

                    parts = value.split(".")
                    if parts[-1] == "":
                        parts = parts[:-1]  # drop the empty end "." split
                    if len(parts) == 0:
                        continue
                    dissection.data[timestamp][key + "_tld"][parts[-1]] += count
                    if len(parts) > 1:
                        dissection.data[timestamp][key + "_sld"][parts[-2]] += count
                        if len(parts) > 2:
                            dissection.data[timestamp][key + "_3ld"][parts[-3]] += count
                            if len(parts) > 3:
                                dissection.data[timestamp][key + "_4ld"][
                                    parts[-4]
                                ] += count
                                if len(parts) > 4:
                                    dissection.data[timestamp][key + "_5ld"][
                                        parts[-5]
                                    ] += count

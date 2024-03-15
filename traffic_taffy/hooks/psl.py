from traffic_taffy.hooks import register_hook
from traffic_taffy.dissector import POST_DISSECT_HOOK
from traffic_taffy.dissection import Dissection

import dnssplitter

splitter = dnssplitter.DNSSplitter()
splitter.init_tree()


@register_hook(POST_DISSECT_HOOK)
def split_dns_names(dissection: Dissection, **kwargs):
    timestamps = dissection.data.keys()

    for timestamp in timestamps:
        keys = list(dissection.data[timestamp].keys())

        for key in keys:
            if str(key).endswith("qname") or str(key).endswith("mname"):
                for value in dissection.data[timestamp][key]:
                    count = dissection.data[timestamp][key][value]
                    results = splitter.search_tree(value)
                    if not results or not results[2]:
                        continue
                    (
                        prefix,
                        registered_domain,
                        registration_point,
                    ) = results
                    if registration_point:
                        dissection.data[timestamp][key + "_prefix"][prefix] += count
                        dissection.data[timestamp][key + "_domain"][
                            registered_domain
                        ] += count
                        dissection.data[timestamp][key + "_psl"][
                            registration_point
                        ] += count

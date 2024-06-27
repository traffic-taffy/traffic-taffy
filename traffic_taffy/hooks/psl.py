from logging import info
import dnssplitter

from traffic_taffy.hooks import register_hook
from traffic_taffy.dissector import POST_DISSECT_HOOK, INIT_HOOK
from traffic_taffy.dissection import Dissection
from traffic_taffy.taffy_config import taffy_default, TaffyConfig

splitter = None

taffy_default("modules.psl.database", "__internal__")


@register_hook(INIT_HOOK)
def init_splitter(**kwargs):
    global splitter

    if not splitter:
        config = TaffyConfig()
        splitter = dnssplitter.DNSSplitter()

        path = config.get_dotnest("modules.psl.database")

        if path == "__internal__":
            splitter.init_tree()
            info("loading PSL data from internal")
        else:
            info(f"loading PSL from {path}")
            splitter.load_psl_file(path)


@register_hook(POST_DISSECT_HOOK)
def split_dns_names(dissection: Dissection, **kwargs):
    init_splitter()

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

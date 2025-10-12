"""Traffic-Taffy plugin to look up addresses in the BLAG blocklist."""
from pathlib import Path
from blagbl import BlagBL
import blagbl
import ipaddress
from logging import error

from traffic_taffy.hooks import register_hook
from traffic_taffy.dissector import POST_DISSECT_HOOK, INIT_HOOK
from traffic_taffy.dissection import Dissection
from traffic_taffy.taffy_config import taffy_default, TaffyConfig

blag = None
blag_ips = None

taffy_default("modules.blag.database", str(blagbl.DEFAULT_STORE.joinpath("blag.zip")))


@register_hook(INIT_HOOK)
def init_blag(**kwargs):
    """Initialize the BLAG block list table."""
    global blag
    global blag_ips

    if blag is None:
        config = TaffyConfig()
        blag_db_path = config.get_dotnest("modules.blag.database")

        if blag_db_path and not Path(blag_db_path).exists():
            error(f"The ip2asn plugin requires a blag.zip file in {blag_db_path}")
            error("Please run blagbl --fetch to download it")

        blag = BlagBL(database=blag_db_path)
        blag.parse_blag_contents()
        blag_ips = blag.ips


@register_hook(POST_DISSECT_HOOK)
def ip_blagbl_lookup(dissection: Dissection, **kwargs):
    """Perform IP address lookups within the BLAG block list."""
    timestamps = dissection.data.keys()

    for timestamp in timestamps:
        keys = list(dissection.data[timestamp].keys())

        for key in keys:
            key = str(key)
            if (
                key.endswith("IP_src") or key.endswith("IP_dst")
                # or key.endswith("IPv6_src")
                # or key.endswith("IPv6_dst")
            ):
                for value in dissection.data[timestamp][key]:
                    try:
                        value = str(ipaddress.IPv4Address(value))
                    except Exception:
                        continue
                    count = dissection.data[timestamp][key][value]

                    if value in blag_ips:
                        for blocklist in blag_ips[value]:
                            dissection.data[timestamp][key + "_blocklist"][
                                blocklist
                            ] += count

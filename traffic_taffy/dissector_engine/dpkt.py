from traffic_taffy.dissector_engine import DissectionEngine
from traffic_taffy.dissection import Dissection, PCAPDissectorLevel
from pcap_parallel import PCAPParallel as pcapp

import dpkt


class DissectionEngineDpkt(DissectionEngine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def load(self) -> Dissection:
        self.init_dissection()
        if isinstance(self.pcap_file, str):
            pcap = dpkt.pcap.Reader(pcapp.open_maybe_compressed(self.pcap_file))
        else:
            # it's an open handle already
            pcap = dpkt.pcap.Reader(self.pcap_file)
        if self.pcap_filter:
            pcap.setfilter(self.pcap_filter)
        pcap.dispatch(self.maximum_count, self.callback)

        self.dissection.calculate_metadata()
        return self.dissection

    def callback(self, timestamp: float, packet: bytes):
        # if binning is requested, save it in a binned time slot
        dissection: Dissection = self.dissection

        dissection.timestamp = int(timestamp)
        if dissection.bin_size:
            dissection.timestamp = (
                dissection.timestamp - dissection.timestamp % dissection.bin_size
            )

        dissection.incr(Dissection.TOTAL_COUNT, dissection.TOTAL_SUBKEY)

        level = self.dissector_level
        if isinstance(level, PCAPDissectorLevel):
            level = level.value
        if level >= PCAPDissectorLevel.THROUGH_IP.value:
            eth = dpkt.ethernet.Ethernet(packet)
            # these names are designed to match scapy names
            dissection.incr("Ethernet.dst", eth.dst)
            dissection.incr("Ethernet.src", eth.src)
            dissection.incr("Ethernet.type", eth.type)

            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data

                IPVER = "IP"
                if ip.v == 6:
                    IPVER = "IPv6"

                # TODO: make sure all these match scapy
                dissection.incr(f"Ethernet.{IPVER}.dst", ip.dst)
                dissection.incr(f"Ethernet.{IPVER}.src", ip.src)
                dissection.incr(f"Ethernet.{IPVER}.df", ip.df)
                dissection.incr(f"Ethernet.{IPVER}.offset", ip.offset)
                dissection.incr(f"Ethernet.{IPVER}.tos", ip.tos)
                dissection.incr(f"Ethernet.{IPVER}.len", ip.len)
                dissection.incr(f"Ethernet.{IPVER}.id", ip.id)
                dissection.incr(f"Ethernet.{IPVER}.hl", ip.hl)
                dissection.incr(f"Ethernet.{IPVER}.rf", ip.rf)
                dissection.incr(f"Ethernet.{IPVER}.p", ip.p)
                dissection.incr(f"Ethernet.{IPVER}.chksum", ip.sum)
                dissection.incr(f"Ethernet.{IPVER}.tos", ip.tos)
                dissection.incr(f"Ethernet.{IPVER}.version", ip.v)
                dissection.incr(f"Ethernet.{IPVER}.ttl", ip.ttl)

                if isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data
                    dissection.incr(f"Ethernet.{IPVER}.UDP.sport", udp.sport)
                    dissection.incr(f"Ethernet.{IPVER}.UDP.dport", udp.dport)
                    dissection.incr(f"Ethernet.{IPVER}.UDP.len", udp.ulen)
                    dissection.incr(f"Ethernet.{IPVER}.UDP.chksum", udp.sum)

                    # TODO: handle DNS and others for level 3

                elif isinstance(ip.data, dpkt.tcp.TCP):
                    # TODO
                    tcp = ip.data
                    dissection.incr(f"Ethernet.{IPVER}.TCP.sport", tcp.sport)
                    dissection.incr(f"Ethernet.{IPVER}.TCP.dport", tcp.dport)
                    dissection.incr(f"Ethernet.{IPVER}.TCP.seq", tcp.seq)
                    dissection.incr(f"Ethernet.{IPVER}.TCP.flags", tcp.flags)
                    # dissection.incr(f"Ethernet.{IPVER}.TCP.reserved", tcp.reserved)
                    dissection.incr(f"Ethernet.{IPVER}.TCP.window", tcp.win)
                    dissection.incr(f"Ethernet.{IPVER}.TCP.chksum", tcp.sum)
                    dissection.incr(f"Ethernet.{IPVER}.TCP.options", tcp.opts)

                    # TODO: handle DNS and others for level 3

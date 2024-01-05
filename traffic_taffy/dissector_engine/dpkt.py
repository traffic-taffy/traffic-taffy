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

    def incr(self, dissection, name, value):
        if name not in self.ignore_list:
            dissection.incr(name, value)

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
            self.incr(dissection, "Ethernet.dst", eth.dst)
            self.incr(dissection, "Ethernet.src", eth.src)
            self.incr(dissection, "Ethernet.type", eth.type)

            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data

                IPVER = "IP"
                if ip.v == 6:
                    IPVER = "IPv6"

                prefix = f"Ethernet.{IPVER}."

                # TODO: make sure all these match scapy
                self.incr(dissection, prefix + "dst", ip.dst)
                self.incr(dissection, prefix + "src", ip.src)
                self.incr(dissection, prefix + "df", ip.df)
                self.incr(dissection, prefix + "offset", ip.offset)
                self.incr(dissection, prefix + "tos", ip.tos)
                self.incr(dissection, prefix + "len", ip.len)
                self.incr(dissection, prefix + "id", ip.id)
                self.incr(dissection, prefix + "hl", ip.hl)
                self.incr(dissection, prefix + "rf", ip.rf)
                self.incr(dissection, prefix + "p", ip.p)
                self.incr(dissection, prefix + "chksum", ip.sum)
                self.incr(dissection, prefix + "tos", ip.tos)
                self.incr(dissection, prefix + "version", ip.v)
                self.incr(dissection, prefix + "ttl", ip.ttl)

                if isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data
                    self.incr(dissection, prefix + "UDP.sport", udp.sport)
                    self.incr(dissection, prefix + "UDP.dport", udp.dport)
                    self.incr(dissection, prefix + "UDP.len", udp.ulen)
                    self.incr(dissection, prefix + "UDP.chksum", udp.sum)

                    # TODO: handle DNS and others for level 3

                elif isinstance(ip.data, dpkt.tcp.TCP):
                    # TODO
                    tcp = ip.data
                    self.incr(dissection, prefix + "TCP.sport", tcp.sport)
                    self.incr(dissection, prefix + "TCP.dport", tcp.dport)
                    self.incr(dissection, prefix + "TCP.seq", tcp.seq)
                    self.incr(dissection, prefix + "TCP.flags", tcp.flags)
                    # self.incr(dissection, prefix + "TCP.reserved", tcp.reserved)
                    self.incr(dissection, prefix + "TCP.window", tcp.win)
                    self.incr(dissection, prefix + "TCP.chksum", tcp.sum)
                    self.incr(dissection, prefix + "TCP.options", tcp.opts)

                    # TODO: handle DNS and others for level 3

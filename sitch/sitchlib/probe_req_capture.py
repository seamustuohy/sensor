#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# This file is part of SITCH-Sensor.
# Copyright © 2017 seamus tuohy, <code@seamustuohy.com>
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the included LICENSE file for details.

from hashlib import sha256
import re
import pyshark

class ProbeReqGatherer(object):

    def __init__(self, salt, results_queue):
        self.probe_requests = []
        self.capture = None
        self.salt = salt
        self.results_queue = results_queue

    def packet_processor(self, pkt):
        """Appends packet to results queue"""
        packet = self.build_packet(pkt)
        self.results_queue.append(packet)

    def start_capture(self, capture_length=100):
        if self.capture == None:
            self.capture = pyshark.LiveRingCapture(interface='mon0',
                                                   bpf_filter='subtype probereq',
                                                   only_summaries=True)
            # TODO Remove after testing
            self.capture.set_debug()
        self.capture.apply_on_packets(self.packet_processor)
        self.capture.sniff(packet_count=capture_length)

    def stop_capture(self):
        self.capture.close()
        self.capture = None

    def build_packet(self, packet):
        packet_data = {"scan_program": "probe_req"}
        # De-identify SSID's
        ssid_sha = sha256()
        # WLAN_MGT : SSID  (ssid)
        ssid_sha.update("{0}{1}".format(packet.wlan_mgt.ssid,
                                        self.salt).encode())
        packet_data.setdefault("SSID", ssid_sha.hexdigest())
        # De-identify MAC addresses
        # Two types of MAC addresses
        # XXXXXXXXX_68:49:a8 ->
        # XX:XX:XX:68:49:a8 ->
        mac_sha = sha256()
        # WLAN : Source address (sa)
        mac_sha.update("{0}{1}".format(packet.wlan.sa,
                                       self.salt).encode())
        packet_data.setdefault("MAC_addr", "{0}{1}".format(packet.wlan.sa[:-8],
                                                       ssid_sha.hexdigest()))
        packet_data.setdefault("sniff_time", packet.sniff_time.isoformat())
        return packet_data

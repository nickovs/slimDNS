# slimDNS
# Simple, Lightweight Implementation of Multicast DNS

# Copyright 2018 Nicko van Someren

# Licensed under the Apache License, Version 2.0 (the "License"); you
# may not use this file except in compliance with the License. You may
# obtain a copy of the License at
# 
# http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.

# SPDX-License-Identifier: Apache-2.0


__version__ = "0.1.0"
__author__ = "Nicko van Someren"
__license__ = "Apache-2.0"

import sys
import time

if sys.implementation.name != "micropython":
    const = lambda x:x
    ticks_ms = lambda : time.clock() * 1000.
    ticks_diff = lambda a, b: b - a
else:
    ticks_ms = time.ticks_ms
    ticks_diff = time.ticks_diff
    
from select import select
try:
    from ustruct import pack_into, unpack_from
except:
    from struct import pack_into, unpack_from

import socket

# The biggest packet we will process
MAX_PACKET_SIZE = const(1024)

MAX_NAME_SEARCH = const(20)

# DNS constants
    
_MDNS_ADDR = '224.0.0.251'
_MDNS_PORT = const(5353);
_DNS_TTL = const(2 * 60) # two minute default TTL

_FLAGS_QR_MASK     = const(0x8000) # query response mask
_FLAGS_QR_QUERY    = const(0x0000) # query
_FLAGS_QR_RESPONSE = const(0x8000) # response

_FLAGS_AA = const(0x0400) # Authorative answer

_CLASS_IN     = const(1)
_CLASS_ANY    = const(255)
_CLASS_MASK   = const(0x7FFF)
_CLASS_UNIQUE = const(0x8000)

_TYPE_A    = const(1)
_TYPE_PTR  = const(12)
_TYPE_TXT  = const(16)
_TYPE_AAAA = const(28)
_TYPE_SRV  = const(33)
_TYPE_ANY  = const(255)

# Convert a dotted IPv4 address string into four bytes, with some
# sanity checks
def dotted_ip_to_bytes(ip):
    l = [int(i) for i in ip.split('.')]
    if len(l) != 4 or any(i<0 or i>255 for i in l):
        raise ValueError
    return bytes(l)

# Convert four bytes into a dotted IPv4 address string, without any
# sanity checks
def bytes_to_dotted_ip(a):
    return ".".join(str(i) for i in a)

# Ensure that a name is in the form of a list of encoded blocks of
# bytes, typically starting as a qualified domain name
def check_name(n):
    if isinstance(n, str):
        n = n.split(".")
        if n[-1] == '':
            n = n[:-1]
    n = [i.encode("UTF8") if isinstance(i, str) else i for i in n]
    return n

# Move the offset past the name to which it currently points
def skip_name_at(buf, o):
    while True:
        l = buf[o]
        if l == 0:
            o += 1
            break
        elif (l & 0xc0) == 0xc0:
            o += 2
            break
        else:
            o += l+1
    return o

# Test if two possibly compressed names are equal
def compare_packed_names(buf, o, packed_name, po=0):
    while packed_name[po] != 0:
        while buf[o] & 0xc0:
            (o,) = unpack_from("!H", buf, o)
            o &= 0x3fff
        while packed_name[po] & 0xc0:
            (po,) = unpack_from("!H", packed_name, po)
            po &= 0x3fff
        l1 = buf[o] +1
        l2 = packed_name[po] +1
        if l1 != l2 or buf[o:o+l1] != packed_name[po:po+l2]:
            return False
        o += l1
        po += l2
    return buf[o] == 0

# Find the memory size needed to pack a name without compression
def name_packed_len(name):
    return sum(len(i)+1 for i in name) + 1

# Pack a name into the start of the buffer
def pack_name(buf, name):
    # We don't support writing with name compression, BIWIOMS
    o = 0
    for part in name:
        pl = len(part)
        buf[o] = pl
        buf[o+1:o+pl+1] = part
        o += pl+1
    buf[o] = 0

# Pack a question into a new array and return it as a memoryview
def pack_question(name, qtype, qclass):
    # Return a pre-packed question as a memoryview
    name = check_name(name)
    name_len = name_packed_len(name)
    buf = bytearray(name_len + 4)
    pack_name(buf, name)
    pack_into("!HH", buf, name_len, qtype, qclass)
    return memoryview(buf)

# Pack an answer into a new array and return it as a memoryview
def pack_answer(name, rtype, rclass, ttl, rdata):
    # Return a pre-packed answer as a memoryview
    name = check_name(name)
    name_len = name_packed_len(name)
    buf = bytearray(name_len + 10 + len(rdata))
    pack_name(buf, name)
    pack_into("!HHIH", buf, name_len, rtype, rclass, ttl, len(rdata))
    buf[name_len+10:] = rdata
    return memoryview(buf)

# Advance the offset past the question to which it points
def skip_question(buf, o):
    o = skip_name_at(buf, o)
    return o + 4

# Advance the offset past the answer to which it points
def skip_answer(buf, o):
    o = skip_name_at(buf, o)
    (rdlen,) = unpack_from("!H", buf, o+8)
    return o + 10 + rdlen

# Test if a questing an answer. Note that this also works for
# comparing a "known answer" in a packet to a local answer. The code
# is asymetric to the extent that the questions my have a type or
# class of ANY
def compare_q_and_a(q_buf, q_offset, a_buf, a_offset=0):
    if not compare_packed_names(q_buf, q_offset, a_buf, a_offset):
        return False
    (q_type, q_class) = unpack_from("!HH", q_buf, skip_name_at(q_buf, q_offset))
    (r_type, r_class) = unpack_from("!HH", a_buf, skip_name_at(a_buf, a_offset))
    if not (q_type == r_type or q_type == _TYPE_ANY):
        return False
    q_class &= _CLASS_MASK
    r_class &= _CLASS_MASK
    return (q_class == r_class or q_class == _TYPE_ANY)


# The main SlimDNSServer class           
class SlimDNSServer:
    def __init__(self, local_addr, hostname=None):
        # If a hostname is give we try to register it
        self.local_addr = local_addr
        self.sock = self._make_socket()
        self.sock.bind(('', _MDNS_PORT))
        self.adverts = []
        self.hostname = None
        self._reply_buffer = None
        self._pending_question = None
        self.answered = False
        if hostname:
            self.advertise_hostname(hostname)

    def _make_socket(self):
        # Note that on devices with a more complete UDP/IP stack it
        # might be necessary to set more options on the socket,
        # incluing things like setting the mutlicast TTL and enabling
        # multicast on the interface.
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        member_info = dotted_ip_to_bytes(_MDNS_ADDR) + dotted_ip_to_bytes(self.local_addr)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, member_info)
        return s

    def advertise_hostname(self, hostname, find_vacant=True):
        # Try to advertise our own IP address under the given hostname
        # If the hostname is taken we try to tack some numbers on the end to make it unique
        hostname = check_name(hostname)
        n = len(hostname)
        if n == 1:
            hostname.append(b"local")
        elif n == 0 or n > 2 or hostname[1] != b'local':
            raise ValueError("hostname should be a single name component")

        ip_bytes = dotted_ip_to_bytes(self.local_addr)
        
        basename = hostname[0]
        for i in range(MAX_NAME_SEARCH):
            if i != 0:
                hostname[0] = basename + b"-"+str(i)
            addr = self.resolve_mdns_address(hostname, True)
            # Some helpful machine might know us and send us our own address
            if not addr or addr == ip_bytes:
                break
            # Even is seaching we have to give up eventually
            if not find_vacant or i == MAX_NAME_SEARCH-1:
                raise ValueError("Name in use")

        A_record = pack_answer(hostname, _TYPE_A, _CLASS_IN, _DNS_TTL, ip_bytes)
        self.adverts.append(A_record)
        self.hostname = hostname

        # We could add a reverse PTR record here.
        # We don't, BIWIOMS

    def process_packet(self, buf, addr):
        # Process a single multicast DNS packet

        (pkt_id, flags, qst_count, ans_count, _, _) = unpack_from("!HHHHHH", buf, 0)
        o = 12
        matches = []
        reply_len = 12
        for i in range(qst_count):
            for a in self.adverts:
                if compare_q_and_a(buf, o, a):
                    matches.append(a)
                    reply_len += len(a)
            o = skip_question(buf, o)

        # In theory we could do known answer suppression here
        # We don't, BIWIOMS

        if self._pending_question:
            for i in range(ans_count):
                if compare_q_and_a(self._pending_question, 0, buf, o):
                    if self._answer_callback(buf[o:skip_answer(buf,o)]):
                        self.answered = True
                o = skip_answer(buf,o)

        if not matches:
            return

        # We could check for duplicates in the answers (which is
        # possible) but we don't, BIWIOMS

        # Since Micropython sockets don't currently support
        # recvfrom_into() we need to have our own buffer for the
        # reply, even though we are now done with the receiving buffer

        if not self._reply_buffer or len(self._reply_buffer) < reply_len:
            # print("Making new reply buffer of len {}".format(reply_len))
            self._reply_buffer = memoryview(bytearray(reply_len))
        
        buf = self._reply_buffer
        pack_into("!HHHHHH", buf, 0,
                  pkt_id, _FLAGS_QR_RESPONSE | _FLAGS_AA,
                  0, len(matches), 0, 0)
        o = 12
        for a in matches:
            l = len(a)
            buf[o:o+l] = a
            o += l

        # print("Sending packed reply: {}".format(bytes(buf[:o])))

        # We fake the handling of unicast replies. If the packet came
        # from the mutlicast port we multicast the reply but if it
        # came from any other port we unicast the reply.
        self.sock.sendto(buf[:o], (_MDNS_ADDR, _MDNS_PORT) if addr[0] == _MDNS_PORT else addr)

    def process_waiting_packets(self):
        # Handle all the packets that can be read immediately and
        # return as soon as none are waiting
        while True:
            readers, _, _ = select([self.sock], [], [], 0)
            if not readers:
                break
            buf, addr = self.sock.recvfrom(MAX_PACKET_SIZE)
            # print("Received {} bytes from {}".format(len(buf), addr))
            if buf and addr[0] != self.local_addr:
                try:
                    self.process_packet(memoryview(buf), addr)
                except IndexError:
                    print("Index error processing packet; probably malformed data")
                except Exception as e:
                    print("Error processing packet: {}".format(e))
                    # raise e

    def run_forever(self):
        # Only really useful once we have stable thread support
        while True:
            readers, _, _ = select([self.sock], [], [], None)
            self.process_waiting_packets()

    def handle_question(self, q, answer_callback, fast=False, retry_count=3):
        # Send our a (packed) question, and send matching replies to
        # the answer_callback function.  This will stop after sending
        # the given number of retries and waiting for the a timeout on
        # each, or sooner if the answer_callback function returns True
        p = bytearray(len(q)+12)
        pack_into("!HHHHHH", p, 0,
                  1, 0, 1, 0, 0, 0)
        p[12:] = q

        self._pending_question = q
        self._answer_callback = answer_callback
        self.answered = False

        try:
            for i in range(retry_count):
                if self.answered:
                    break
                self.sock.sendto(p, (_MDNS_ADDR, _MDNS_PORT))
                timeout = ticks_ms() + (250 if fast else 1000)
                while not self.answered:
                    sel_time = ticks_diff(timeout, ticks_ms())
                    if sel_time <= 0:
                        break
                    (rr, _, _) = select([self.sock], [], [], sel_time/1000.0)
                    if rr:
                        self.process_waiting_packets()
        finally:
            self._pending_question = None
            self._answer_callback = None

    def resolve_mdns_address(self, hostname, fast=False):
        # Look up an IPv4 address for a hostname using mDNS.
        q = pack_question(hostname, _TYPE_A, _CLASS_IN)
        answer = []
        def _answer_handler(a):
            addr_offset = skip_name_at(a, 0) + 10
            answer.append(a[addr_offset:addr_offset+4])
            return True
        self.handle_question(q, _answer_handler, fast)
        return bytes(answer[0]) if answer else None

    
def test():
    import network
    sta_if = network.WLAN(network.STA_IF)
    local_addr = sta_if.ifconfig()[0]
    server = SlimDNSServer(local_addr, "micropython")
    server.run_forever()

/*
Copyright 2019-present Barefoot Networks, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "dpdk.p4"

typedef bit<48> MacAddr_t;
typedef bit<32> IPv4_t;

enum bit<16> EtherType_t {
    IPv4 = 0x0800
}

header ethernet_t {
    MacAddr_t dst_addr;
    MacAddr_t src_addr;
    EtherType_t ether_type;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<6> dscp;
    bit<2> ecn;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    IPv4_t src_addr;
    IPv4_t dst_addr;
}

struct Hdr {
    ethernet_t ethernet;
    ipv4_t ipv4;
}

// user-defined metadata
// empty for now
struct Meta { }

parser MyParser(packet_in packet, out Hdr hdr, inout Meta meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            EtherType_t.IPv4 : parse_ipv4;
            _ : accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

control MyDeparser(packet_out packet, inout Hdr hdr, in Meta meta,
                   inout standard_metadata_t standard_metadata) {
    apply {
        packet.emit(hdr);
    }
}

action drop() {
    mark_to_drop();
}

control L2Pipe(inout Hdr hdr, inout Meta meta,
               inout standard_metadata_t standard_metadata) {
    action fwd(PortId_t port) {
        standard_metadata.egress_port = port;
    }

    @dpdk_implementation("cuckoo_hash")
    table dmac {
        key = {
            hdr.ethernet.dst_addr: exact;
        }
        actions = { fwd; drop; }
        size = 4096;
        default_action = drop();
    }

    apply {
        dmac.apply();
    }
}

control L3Pipe(inout Hdr hdr, inout Meta meta,
               inout standard_metadata_t standard_metadata) {
    action fwd(PortId_t port, MacAddr_t smac, MacAddr_t dmac) {
        standard_metadata.egress_port = port;
        hdr.ethernet.src_addr = smac;
        hdr.ethernet.dst_addr = dmac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table fib {
        key = {
            hdr.ipv4.dst_addr: lpm;
        }
        actions = { fwd; drop; }
        size = 16384;
        const default_action = drop();
    }

    table rmac {
        key = {
            hdr.ethernet.src_addr: exact;
        }
        actions = { NoAction; }
        const default_action = NoAction();
    }

    apply {
        if (hdr.ipv4.isValid() && rmac.apply().hit) {
            fib.apply();
        } else {
            drop();  // or send to a L2Pipe?
        }
    }
}

control ACLPipe(inout Hdr hdr, inout Meta meta,
                inout standard_metadata_t standard_metadata) {
    apply {
        // TODO
    }
}

Pipeline(MyParser(), L2Pipe(), MyDeparser()) pipe0;

Pipeline(MyParser(), L3Pipe(), MyDeparser()) pipe1;

Pipelines(pipe0, pipe1) main;

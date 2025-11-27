#!/usr/bin/env bash

set -euo pipefail

FILTER_1='( ( eth.addr == f0:18:98:5e:ff:9f ) and ( ( ( (ip.src == 192.168.0.16) and (ip.dst == 192.168.0.13) ) or ( (ip.src == 192.168.0.13) and (ip.dst == 192.168.0.16) ) ) and tcp and not icmp ) or ( ( arp.src.hw_mac == f0:18:98:5e:ff:9f ) and ( ( arp.dst.hw_mac == bc:1c:81:4b:ae:ba ) or ( arp.dst.hw_mac == 48:4b:aa:2c:d8:f9 ) ) ) )'


FILTER_1='( ( eth.addr == f0:18:98:5e:ff:9f ) and ( ( ( (ip.src == 192.168.0.16) and (ip.dst == 192.168.0.13) ) or ( (ip.src == 192.168.0.13) and (ip.dst == 192.168.0.16) ) ) and tcp and not icmp ) or ( ( arp.src.hw_mac == f0:18:98:5e:ff:9f ) and ( ( arp.dst.hw_mac == bc:1c:81:4b:ae:ba ) or ( arp.dst.hw_mac == 48:4b:aa:2c:d8:f9 ) ) ) )'

FILTER_2='( ( eth.addr == f0:18:98:5e:ff:9f ) and ( ( ( (ip.src == 192.168.0.16) and (ip.dst == 192.168.0.13) ) or ( (ip.src == 192.168.0.13) and (ip.dst == 192.168.0.16) ) ) and not icmp and tcp ) or ( ( arp.src.hw_mac == f0:18:98:5e:ff:9f ) and ( ( arp.dst.hw_mac == bc:1c:81:4b:ae:ba ) or ( arp.dst.hw_mac == 48:4b:aa:2c:d8:f9 ) ) ) )'

FILTER_3="$FILTER_2"
FILTER_4="eth.addr == f0:18:98:5e:ff:9f and (((ip.addr == 192.168.0.24) and !icmp and tcp) or (arp.src.hw_mac == f0:18:98:5e:ff:9f and (arp.dst.hw_mac == 04:32:f4:45:17:b3 or arp.dst.hw_mac == 88:36:6c:d7:1c:56)))"
FILTER_5="eth.addr == f0:18:98:5e:ff:9f and (((ip.addr == 192.168.0.24) and !icmp and tcp) or (arp.src.hw_mac == f0:18:98:5e:ff:9f and (arp.dst.hw_mac == 04:32:f4:45:17:b3 or arp.dst.hw_mac == 88:36:6c:d7:1c:56)))"
FILTER_6="eth.addr == f0:18:98:5e:ff:9f and (((ip.addr == 192.168.0.24) and !icmp and tcp) or (arp.src.hw_mac == f0:18:98:5e:ff:9f and (arp.dst.hw_mac == 04:32:f4:45:17:b3 or arp.dst.hw_mac == 88:36:6c:d7:1c:56)))"
ARR=(1 2 3 4 5 6)

FIELDS=(
  frame.len
  ip.proto
  ip.len
  ip.ttl
  ip.flags
  ip.hdr_len
  arp
  tcp.flags.syn
  tcp.flags.ack
  tcp.flags.reset
  tcp.window_size
  icmp
  tcp.checksum.status
  tcp.dstport
  tcp.srcport
  tcp.flags
  tcp.len
  tcp.time_delta
  tcp.urgent_pointer
  udp.srcport
  udp.dstport
)

for i in "${ARR[@]}"; do
  PCAP="mitm-arpspoofing-${i}-dec.pcap"
  OUT="arp_spoofing_${i}_attack.tsv"

  FILTER_VAR="FILTER_${i}"
  FILTER="${!FILTER_VAR}"

  EARGS=()
  for f in "${FIELDS[@]}"; do
    EARGS+=( -e "$f" )
  done

  echo "Exporting attack -> $OUT (file $PCAP)"
  tshark -r "$PCAP" -Y "$FILTER" -T fields -E header=y -E separator=$'\t' "${EARGS[@]}" > "$OUT"
done


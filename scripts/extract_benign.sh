#!/usr/bin/env bash

set -euo pipefail

FILTER_1=""

ARR=(1)

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
  PCAP="benign-dec.pcap"
  OUT="arp_spoofing_${i}_benign.tsv"

  FILTER_VAR="FILTER_${i}"
  FILTER="${!FILTER_VAR}"

  EARGS=()
  for f in "${FIELDS[@]}"; do
    EARGS+=( -e "$f" )
  done

  echo "Exporting benign -> $OUT (file $PCAP)"

  if [[ -z "$FILTER" ]]; then
    tshark -r "$PCAP" -T fields -E header=y -E separator=$'\t' "${EARGS[@]}" > "$OUT"
  else
    tshark -r "$PCAP" -Y "$FILTER" -T fields -E header=y -E separator=$'\t' "${EARGS[@]}" > "$OUT"
  fi
done

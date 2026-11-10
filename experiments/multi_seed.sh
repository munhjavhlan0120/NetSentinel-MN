#!/usr/bin/env bash
# Өөр санамсаргүй үрээр (seed) өгөгдөл үүсгэж үнэлгээг давтана (үр дүнгийн тогтвортой байдал)
set -e
for s in "$@"; do
  python3 tools/gen_traffic.py --seed "$s" --out "data/lab_s$s.pcap" --labels "data/labels_s$s.csv"
  python3 experiments/evaluate.py --pcap "data/lab_s$s.pcap" --labels "data/labels_s$s.csv" --out "results/seed_$s"
done

# NetSentinel — Python дээр суурилсан сүлжээний гүйцэтгэл ба аюулгүй байдлын аномали хянах систем

Дипломын ажлын программ хангамж. Гурван түвшний хосолмол (hybrid) илрүүлэлт:
1. **Дүрэм** — порт скан, удаан скан, host sweep, SYN flood, ICMP flood, brute force, ARP spoofing, DNS tunneling
2. **Статистик (EWMA + z-оноо)** — урсгалын эзлэхүүний огцом хазайлт
3. **ML (Isolation Forest)** — зан төлөвийн шинжээр урьд үл мэдэгдэх аномали

Гүйцэтгэл: RTT, jitter, пакет алдагдал (ICMP/TCP probe), интерфэйсийн дамжуулах хурд; SLA босго + EWMA + baseline шинэчлэл.
Сэрэмжлүүлэг: консол, JSONL лог, SQLite, Telegram. Веб самбар: Flask + Chart.js.

## Суулгах (Ubuntu)
```bash
sudo apt install python3-venv libpcap-dev
python3 -m venv venv && . venv/bin/activate
pip install -r requirements.txt
```

## Ажиллуулах
```bash
python main.py probe                          # гүйцэтгэлийн нэг удаагийн хэмжилт
sudo venv/bin/python main.py train --pcap normal.pcap   # хэвийн урсгалаар ML сургах
sudo venv/bin/python main.py live             # бодит цагийн хяналт (root / CAP_NET_RAW)
python main.py pcap --pcap capture.pcap       # PCAP файл шинжлэх
python main.py dashboard                      # http://127.0.0.1:8050
```
Telegram: `config.yaml`-д `telegram.enabled: true`, дараа нь `export NS_TG_TOKEN=... NS_TG_CHAT=...`.

## Туршилтыг давтах
```bash
python tools/gen_traffic.py --out data/lab.pcap --labels data/labels.csv
python experiments/evaluate.py      # results/metrics.json
python experiments/perf_sim.py      # results/perf_metrics.json
python experiments/plots.py         # results/fig/*.pdf
./experiments/multi_seed.sh 11 23 42
python -m pytest -q tests
```

## Лабораторийн бодит туршилт (VirtualBox)
Kali (халдагч) + Ubuntu (хамгаалагдсан сервер, NetSentinel) + клиент, Host-only сүлжээ 192.168.56.0/24:
```bash
nmap -sS -p 1-1000 192.168.56.100            # port_scan
nmap -sS -T1 -p 1-200 192.168.56.100         # slow_scan
nmap -sn 192.168.56.0/24                     # host_sweep
sudo hping3 -S --flood --rand-source -p 80 192.168.56.100   # syn_flood
sudo hping3 --icmp --flood 192.168.56.100    # icmp_flood
hydra -l root -P rockyou.txt ssh://192.168.56.101           # brute_force
sudo arpspoof -i eth0 -t 192.168.56.20 192.168.56.1         # arp_spoof
```
Зөвхөн өөрийн хяналтад байгаа тусгаарлагдсан лабораторийн сүлжээнд туршина.

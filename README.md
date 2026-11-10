# NetSentinel-MN

**Хосолмол аргад суурилсан сүлжээний аюулгүй байдлын хяналтын нээлттэй систем**
*An open-source hybrid network intrusion detection system with a Mongolian dashboard and Telegram alerts*

NetSentinel-MN нь сүлжээний урсгалыг бодит хугацаанд (эсвэл PCAP файлаас) шинжилж, халдлагыг гурван аргаар зэрэг илрүүлээд, үр дүнг монгол хэл дээрх веб самбар болон Telegram-аар администраторт хүргэдэг систем юм. ШУТИС-ийн Мэдээлэл, холбооны технологийн сургуулийн Кибер аюулгүй байдлын тэнхимд дипломын ажлын хүрээнд хөгжүүлэв.

## Онцлог

- **Хосолмол илрүүлэлт**
  1. **Дүрэм**: порт скан, удаан скан, хост скан, SYN flood, ICMP flood, SSH нууц үг таах, ARP spoofing, DNS tunneling
  2. **Статистик (EWMA + z-оноо)**: урсгалын хэмжээний огцом өөрчлөлт
  3. **Машин сургалт (Isolation Forest)**: зөвхөн хэвийн урсгалаар сургаж, урьд өмнө үзээгүй хэвийн бус үйлдлийг илрүүлнэ
- **Хоёр горим**: сүлжээний интерфейсээс бодит хугацаанд, эсвэл хадгалсан PCAP файлаас
- **Ойлгомжтой**: давхардсан дохиог 60 секундэд нэгтгэж, сэрэмжлүүлэг бүрийг төрөл, эх үүсвэр, зорилтоор тайлбарлана
- **Мэдэгдэл**: Flask веб самбар, Telegram, консол, JSONL лог, SQLite
- **Хөнгөн**: энгийн компьютер дээр ажиллаж, зөвхөн 5 секундийн цонхны нэгтгэсэн үзүүлэлтийг хадгалдаг (өдөрт ≈10 МБ)

## Үр дүн (4 урсгалын дундаж)

| Илрүүлэгч | F1 |
|---|---|
| Дүрэм | 0.942 |
| EWMA (статистик) | 0.747 |
| Isolation Forest (ML) | 0.420 |
| **Дүрэм ∪ ML (хосолмол)** | **0.953** |
| Дүрэм ∪ (EWMA ∩ ML) | 0.948 |

Хосолмол илрүүлэгч: precision 0.986, recall 0.924, хуурамч эерэг 0.4%. Зан төлөвийн шинж ашигласнаар Isolation Forest-ийн precision 0.893-аас 0.969 болсон. Найман төрлийн халдлага бүгд илэрсэн. Халдлага эхэлснээс 10 секундийн дотор самбарт харагдана.

> **Анхааруулга:** дээрх үр дүн нь Scapy-аар загварчилсан 30 клиенттэй сүлжээний шошготой урсгал (4 урсгал, тус бүр ≈40 минут, ≈160 мянган пакет) дээр гарсан. Бодит байгууллагын сүлжээнд турших нь цаашдын ажил юм.

## Суулгах (Ubuntu 22.04/24.04)

```bash
sudo apt install -y python3-venv libpcap-dev
git clone https://github.com/munhjavhlan0120/NetSentinel-MN.git
cd NetSentinel-MN
python3 -m venv venv && . venv/bin/activate
pip install -r requirements.txt
```

## Ажиллуулах

```bash
sudo venv/bin/python main.py train --pcap normal.pcap   # хэвийн урсгалаар ML сургах
sudo venv/bin/python main.py live                       # бодит хугацааны хяналт
python main.py pcap --pcap capture.pcap                 # PCAP файл шинжлэх
python main.py dashboard                                # http://127.0.0.1:8050
python main.py probe                                    # сүлжээний гүйцэтгэлийн хэмжилт
```

### Telegram мэдэгдэл

1. Telegram дээр @BotFather-аар бот үүсгэж токен авна.
2. `config.yaml` дотор `telegram.enabled: true` болгоно.
3. Токен болон chat id-г **кодонд биш**, орчны хувьсагчаар өгнө:

```bash
export NS_TG_TOKEN="<токен>"
export NS_TG_CHAT="<chat id>"
```

## Туршилтыг давтах

```bash
python tools/gen_traffic.py --out data/lab.pcap --labels data/labels.csv
python experiments/evaluate.py          # results/metrics.json
./experiments/multi_seed.sh 11 23 42    # 4 урсгалын үнэлгээ
python experiments/plots.py             # results/fig/*.pdf
python -m pytest -q tests
```

PCAP файлууд том тул repository-д ороогүй. Дээрх `gen_traffic.py` скриптээр яг ижил урсгалыг дахин үүсгэнэ.

## Бүтэц

```
netsentinel/          системийн цөм
  capture.py          пакет барих (интерфейс / PCAP)
  features.py         5 секундийн цонх, 22 шинж
  detectors/          rules.py, statistical.py (EWMA), ml.py (Isolation Forest)
  engine.py           дамжлага, давхардал шүүлт
  alerting.py         консол, лог, SQLite, Telegram
  dashboard.py        Flask веб самбар
tools/gen_traffic.py  шошготой туршилтын урсгал үүсгэгч
experiments/          үнэлгээ, график
results/              туршилтын үр дүн
tests/                нэгжийн тест
deploy/               systemd үйлчилгээ
```

## Ёс зүйн анхааруулга

Халдлагын туршилтыг зөвхөн өөрийн хяналтад байгаа, тусгаарлагдсан лабораторийн сүлжээнд хийнэ.

## Зохиогч

- Ц.Мөнхжавхлан, ШУТИС, МХТС, Кибер аюулгүй байдлын тэнхим
- Удирдагч багш: Доктор (Ph.D) А.Гэрэлцэцэг
- Хамтран зохиогч: Доктор (Ph.D) Ц.Энхтөр

## Лиценз

MIT License. Дэлгэрэнгүйг [LICENSE](LICENSE) файлаас үзнэ үү.

# Packet Analyzer

A Deep Packet Inspection (DPI) engine written in Java. It reads a PCAP file,
finds which app each connection belongs to, and can block traffic by app or domain.

## Build

```
javac -d bin src/main/java/com/dpi/types/*.java src/main/java/com/dpi/pcap/*.java src/main/java/com/dpi/parser/*.java src/main/java/com/dpi/extractor/*.java src/main/java/com/dpi/threading/*.java src/main/java/com/dpi/engine/*.java
```

## Make test traffic

```
python3 generate_test_pcap.py
```

## Run (single thread)

```
java -cp bin com.dpi.engine.DPIEngine test_dpi.pcap output.pcap
java -cp bin com.dpi.engine.DPIEngine test_dpi.pcap output.pcap --block-app YouTube
java -cp bin com.dpi.engine.DPIEngine test_dpi.pcap output.pcap --block-domain facebook.com
java -cp bin com.dpi.engine.DPIEngine test_dpi.pcap output.pcap --block-ip 192.168.1.50
```

## Run (multi thread)

```
java -cp bin com.dpi.engine.MultiThreadedDPIEngine test_dpi.pcap output.pcap
java -cp bin com.dpi.engine.MultiThreadedDPIEngine test_dpi.pcap output.pcap --threads 4 --block-app YouTube
```

## How it works

- PcapReader reads packets from the file
- PacketParser reads the Ethernet, IP, TCP and UDP headers
- Extractors read the domain from TLS (SNI), HTTP (Host) and DNS
- Each connection is tracked by its 5-tuple and labelled with an app
- RuleManager decides if a packet is blocked
- In multi-thread mode, a load balancer hands packets to worker threads

## Known problems

- The output pcap is not written yet
- In multi-thread mode, blocked counts can change between runs
- --block-ip does not work in multi-thread mode

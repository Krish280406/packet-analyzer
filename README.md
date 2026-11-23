# Packet Analyzer (DPI Engine)

A Deep Packet Inspection (DPI) engine written in Java. It reads a PCAP file,
works out which app each connection belongs to (YouTube, Facebook, etc.) using the
TLS SNI, HTTP Host header or DNS query, and applies block rules by app, domain or IP.

No frameworks, no database. Plain Java 11+, built with Maven.

## How it works

```
PcapReader -> PacketParser -> FiveTuple -> Connection (flow table)
          -> classifyFlow (SNI / HTTP Host / DNS) -> RuleManager -> counters + report
```

- PcapReader reads the 24 byte global header and then each packet
- PacketParser reads the Ethernet, IPv4, TCP and UDP headers
- Extractors pull the domain name out of the TLS ClientHello, HTTP request or DNS query
- Each flow is tracked by its 5-tuple, so a flow only needs to be classified once
- RuleManager decides if a packet is blocked (by source IP, app or domain)
- Multi-thread mode: a load balancer hands packets round-robin to worker threads
  through blocking queues. A CountDownLatch tells the main thread when the workers finish

## Project structure

```
src/main/java/com/dpi/
  engine/     DPIEngine, MultiThreadedDPIEngine, LoadBalancerThread, FastPathThread, RuleManager
  parser/     PacketParser, ParsedPacket
  extractor/  SNIExtractor, HTTPHostExtractor, DNSExtractor
  pcap/       PcapReader, RawPacket
  types/      AppType, Connection, ConnectionState, DPIStats, FiveTuple, PacketAction
  threading/  ThreadSafeQueue
src/test/java/com/dpi/   JUnit tests (23)
generate_test_pcap.py    makes test_dpi.pcap
```

## Build and test

```
mvn clean package
```

## Make test traffic

```
python3 generate_test_pcap.py
```

This creates test_dpi.pcap with 77 packets: 16 TLS connections, 2 HTTP, 4 DNS and 5 packets from a blocked IP.

## Run (single thread)

```
java -jar target/packet-analyzer-2.0.0.jar test_dpi.pcap output.pcap
java -jar target/packet-analyzer-2.0.0.jar test_dpi.pcap output.pcap --block-app YouTube
java -jar target/packet-analyzer-2.0.0.jar test_dpi.pcap output.pcap --block-domain facebook.com
java -jar target/packet-analyzer-2.0.0.jar test_dpi.pcap output.pcap --block-ip 192.168.1.50
```

## Run (multi thread)

```
java -cp target/packet-analyzer-2.0.0.jar com.dpi.engine.MultiThreadedDPIEngine test_dpi.pcap output.pcap --threads 4
java -cp target/packet-analyzer-2.0.0.jar com.dpi.engine.MultiThreadedDPIEngine test_dpi.pcap output.pcap --threads 4 --block-app YouTube
```

## Results I checked

- Blocking YouTube drops 1 packet (the ClientHello). The SYN and ACK before it were already forwarded
- Blocking facebook.com drops 2 (the ClientHello and the DNS lookup)
- Blocking IP 192.168.1.50 drops 5 in single thread mode

## Known problems (things I plan to fix)

- The output pcap is written by DPIEngine (single thread). The multi-thread engine does not write it yet
- --block-ip does not work in multi-thread mode (0 dropped instead of 5), because the two engines pack IPs in different byte order
- In multi-thread mode, packets of one flow can go to different workers, so blocked counts can depend on timing
- HTTP flows are labelled HTTPS
- DNS lookups are labelled DNS, not by the domain asked, so blocking an app does not block its DNS lookup
- App detection uses substring matching, so pineapple.com is labelled Apple
- Domain blocking uses substring matching, so facebook.com also blocks notfacebook.com
- An unknown app name in --block-app crashes
- A TLS ClientHello split over two packets is not detected
Ecat > README.md << 'EOF'
# Packet Analyzer (DPI Engine)

A Deep Packet Inspection (DPI) engine written in Java. It reads a PCAP file,
works out which app each connection belongs to (YouTube, Facebook, etc.) using the
TLS SNI, HTTP Host header or DNS query, and applies block rules by app, domain or IP.

No frameworks, no database. Plain Java 11+, built with Maven.

## How it works

```
PcapReader -> PacketParser -> FiveTuple -> Connection (flow table)
          -> classifyFlow (SNI / HTTP Host / DNS) -> RuleManager -> counters + report
```

- PcapReader reads the 24 byte global header and then each packet
- PacketParser reads the Ethernet, IPv4, TCP and UDP headers
- Extractors pull the domain name out of the TLS ClientHello, HTTP request or DNS query
- Each flow is tracked by its 5-tuple, so a flow only needs to be classified once
- RuleManager decides if a packet is blocked (by source IP, app or domain)
- Multi-thread mode: a load balancer hands packets round-robin to worker threads
  through blocking queues. A CountDownLatch tells the main thread when the workers finish

## Project structure

```
src/main/java/com/dpi/
  engine/     DPIEngine, MultiThreadedDPIEngine, LoadBalancerThread, FastPathThread, RuleManager
  parser/     PacketParser, ParsedPacket
  extractor/  SNIExtractor, HTTPHostExtractor, DNSExtractor
  pcap/       PcapReader, RawPacket
  types/      AppType, Connection, ConnectionState, DPIStats, FiveTuple, PacketAction
  threading/  ThreadSafeQueue
src/test/java/com/dpi/   JUnit tests (23)
generate_test_pcap.py    makes test_dpi.pcap
```

## Build and test

```
mvn clean package
```

## Make test traffic

```
python3 generate_test_pcap.py
```

This creates test_dpi.pcap with 77 packets: 16 TLS connections, 2 HTTP, 4 DNS and 5 packets from a blocked IP.

## Run (single thread)

```
java -jar target/packet-analyzer-2.0.0.jar test_dpi.pcap output.pcap
java -jar target/packet-analyzer-2.0.0.jar test_dpi.pcap output.pcap --block-app YouTube
java -jar target/packet-analyzer-2.0.0.jar test_dpi.pcap output.pcap --block-domain facebook.com
java -jar target/packet-analyzer-2.0.0.jar test_dpi.pcap output.pcap --block-ip 192.168.1.50
```

## Run (multi thread)

```
java -cp target/packet-analyzer-2.0.0.jar com.dpi.engine.MultiThreadedDPIEngine test_dpi.pcap output.pcap --threads 4
java -cp target/packet-analyzer-2.0.0.jar com.dpi.engine.MultiThreadedDPIEngine test_dpi.pcap output.pcap --threads 4 --block-app YouTube
```

## Results I checked

- Blocking YouTube drops 1 packet (the ClientHello). The SYN and ACK before it were already forwarded
- Blocking facebook.com drops 2 (the ClientHello and the DNS lookup)
- Blocking IP 192.168.1.50 drops 5 in single thread mode

## Known problems (things I plan to fix)

- The output pcap is written by DPIEngine (single thread). The multi-thread engine does not write it yet
- --block-ip does not work in multi-thread mode (0 dropped instead of 5), because the two engines pack IPs in different byte order
- In multi-thread mode, packets of one flow can go to different workers, so blocked counts can depend on timing
- HTTP flows are labelled HTTPS
- DNS lookups are labelled DNS, not by the domain asked, so blocking an app does not block its DNS lookup
- App detection uses substring matching, so pineapple.com is labelled Apple
- Domain blocking uses substring matching, so facebook.com also blocks notfacebook.com
- An unknown app name in --block-app crashes
- A TLS ClientHello split over two packets is not detected

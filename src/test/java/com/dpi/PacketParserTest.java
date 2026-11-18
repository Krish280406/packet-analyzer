package com.dpi;

import static org.junit.Assert.*;

import com.dpi.parser.PacketParser;
import com.dpi.parser.ParsedPacket;
import com.dpi.pcap.RawPacket;
import org.junit.Test;

public class PacketParserTest {

    @Test
    public void parsesTcpSynPacket() {
        RawPacket raw = TestPackets.tcpPacket("192.168.1.100", "142.250.185.206", 50000, 443, 0x02, new byte[0]);
        ParsedPacket p = new ParsedPacket();

        assertTrue(PacketParser.parse(raw, p));
        assertTrue(p.hasIP);
        assertTrue(p.hasTCP);
        assertFalse(p.hasUDP);
        assertEquals("192.168.1.100", p.srcIp);
        assertEquals("142.250.185.206", p.destIp);
        assertEquals(50000, p.srcPort);
        assertEquals(443, p.destPort);
        assertEquals("SYN", PacketParser.tcpFlagsToString(p.tcpFlags));
        assertEquals(0, p.payloadLength);
    }

    @Test
    public void tcpPayloadIsExtractedAfterHeaders() {
        byte[] hello = TestPackets.clientHello("www.youtube.com");
        RawPacket raw = TestPackets.tcpPacket("192.168.1.100", "142.250.185.110", 50001, 443, 0x18, hello);
        ParsedPacket p = new ParsedPacket();

        assertTrue(PacketParser.parse(raw, p));
        assertEquals(hello.length, p.payloadLength);
        assertArrayEquals(hello, p.payloadData);
        assertEquals("ACK PSH", PacketParser.tcpFlagsToString(p.tcpFlags));
    }

    @Test
    public void parsesUdpDnsPacket() {
        byte[] dns = TestPackets.dnsQuery("www.google.com");
        RawPacket raw = TestPackets.udpPacket("192.168.1.100", "8.8.8.8", 51000, 53, dns);
        ParsedPacket p = new ParsedPacket();

        assertTrue(PacketParser.parse(raw, p));
        assertTrue(p.hasUDP);
        assertFalse(p.hasTCP);
        assertEquals(53, p.destPort);
        assertEquals(dns.length, p.payloadLength);
    }

    @Test
    public void rejectsTooShortAndSkipsNonIp() {
        RawPacket tiny = new RawPacket();
        tiny.data = new byte[10];
        assertFalse(PacketParser.parse(tiny, new ParsedPacket()));

        ParsedPacket arp = new ParsedPacket();
        assertTrue(PacketParser.parse(TestPackets.arpPacket(), arp));
        assertEquals(0x0806, arp.etherType);
        assertFalse(arp.hasIP);
    }
}

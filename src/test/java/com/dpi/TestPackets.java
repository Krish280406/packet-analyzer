package com.dpi;

import com.dpi.pcap.RawPacket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class TestPackets {

    public static byte[] clientHello(String host) {
        byte[] h = host.getBytes(StandardCharsets.US_ASCII);

        ByteBuffer sni = ByteBuffer.allocate(2 + 1 + 2 + h.length);
        sni.putShort((short) (1 + 2 + h.length));
        sni.put((byte) 0);
        sni.putShort((short) h.length);
        sni.put(h);
        byte[] sniData = sni.array();

        ByteBuffer ext = ByteBuffer.allocate(4 + sniData.length + 4 + 3);
        ext.putShort((short) 0).putShort((short) sniData.length).put(sniData);
        ext.putShort((short) 0x002b).putShort((short) 3).put((byte) 2).putShort((short) 0x0304);
        byte[] extBytes = ext.array();

        ByteBuffer body = ByteBuffer.allocate(45 + extBytes.length);
        body.putShort((short) 0x0303);
        body.put(new byte[32]);
        body.put((byte) 0);
        body.putShort((short) 4).putShort((short) 0x1301).putShort((short) 0x1302);
        body.put((byte) 1).put((byte) 0);
        body.putShort((short) extBytes.length).put(extBytes);
        byte[] bodyBytes = body.array();

        ByteBuffer hs = ByteBuffer.allocate(4 + bodyBytes.length);
        hs.put((byte) 0x01);
        hs.put((byte) (bodyBytes.length >> 16)).put((byte) (bodyBytes.length >> 8)).put((byte) bodyBytes.length);
        hs.put(bodyBytes);
        byte[] hsBytes = hs.array();

        ByteBuffer rec = ByteBuffer.allocate(5 + hsBytes.length);
        rec.put((byte) 0x16).putShort((short) 0x0301).putShort((short) hsBytes.length);
        rec.put(hsBytes);
        return rec.array();
    }

    public static byte[] dnsQuery(String domain) {
        ByteBuffer b = ByteBuffer.allocate(12 + domain.length() + 2 + 4);
        b.putShort((short) 0x1234).putShort((short) 0x0100).putShort((short) 1);
        b.putShort((short) 0).putShort((short) 0).putShort((short) 0);
        for (String label : domain.split("\\.")) {
            b.put((byte) label.length());
            b.put(label.getBytes(StandardCharsets.US_ASCII));
        }
        b.put((byte) 0).putShort((short) 1).putShort((short) 1);
        return b.array();
    }

    public static RawPacket tcpPacket(String srcIp, String dstIp, int srcPort, int dstPort,
                                      int flags, byte[] payload) {
        ByteBuffer t = ByteBuffer.allocate(20 + payload.length);
        t.putShort((short) srcPort).putShort((short) dstPort).putInt(1000).putInt(0);
        t.put((byte) 0x50).put((byte) flags).putShort((short) 65535);
        t.putShort((short) 0).putShort((short) 0);
        t.put(payload);
        return ipPacket(srcIp, dstIp, 6, t.array());
    }

    public static RawPacket udpPacket(String srcIp, String dstIp, int srcPort, int dstPort,
                                      byte[] payload) {
        ByteBuffer u = ByteBuffer.allocate(8 + payload.length);
        u.putShort((short) srcPort).putShort((short) dstPort);
        u.putShort((short) (8 + payload.length)).putShort((short) 0);
        u.put(payload);
        return ipPacket(srcIp, dstIp, 17, u.array());
    }

    public static RawPacket arpPacket() {
        RawPacket p = new RawPacket();
        p.data = new byte[42];
        p.data[12] = 0x08;
        p.data[13] = 0x06;
        return p;
    }

    private static RawPacket ipPacket(String src, String dst, int proto, byte[] l4) {
        ByteBuffer b = ByteBuffer.allocate(14 + 20 + l4.length);
        b.put(new byte[12]);
        b.putShort((short) 0x0800);
        b.put((byte) 0x45).put((byte) 0).putShort((short) (20 + l4.length));
        b.putShort((short) 1).putShort((short) 0x4000);
        b.put((byte) 64).put((byte) proto).putShort((short) 0);
        b.put(ipBytes(src)).put(ipBytes(dst));
        b.put(l4);
        RawPacket p = new RawPacket();
        p.data = b.array();
        return p;
    }

    private static byte[] ipBytes(String ip) {
        String[] parts = ip.split("\\.");
        byte[] out = new byte[4];
        for (int i = 0; i < 4; i++) out[i] = (byte) Integer.parseInt(parts[i]);
        return out;
    }
}

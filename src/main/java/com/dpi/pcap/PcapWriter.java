package com.dpi.pcap;

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PcapWriter {
    private OutputStream out;

    public boolean open(String filename) throws IOException {
        close();
        out = new BufferedOutputStream(new FileOutputStream(filename));

        ByteBuffer bb = ByteBuffer.allocate(24);
        bb.order(ByteOrder.LITTLE_ENDIAN);
        bb.putInt(0xa1b2c3d4);   // magic number
        bb.putShort((short) 2);  // version major
        bb.putShort((short) 4);  // version minor
        bb.putInt(0);            // timezone
        bb.putInt(0);            // sigfigs
        bb.putInt(65535);        // snaplen
        bb.putInt(1);            // link type: Ethernet
        out.write(bb.array());
        return true;
    }

    public synchronized void writePacket(RawPacket packet) throws IOException {
        if (out == null) {
            throw new IOException("PcapWriter is not open");
        }

        ByteBuffer bb = ByteBuffer.allocate(16);
        bb.order(ByteOrder.LITTLE_ENDIAN);
        bb.putInt((int) packet.header.tsSec);
        bb.putInt((int) packet.header.tsUsec);
        bb.putInt(packet.data.length);   // inclLen: bytes actually stored
        bb.putInt(packet.data.length);   // origLen
        out.write(bb.array());
        out.write(packet.data);
    }

    public void close() throws IOException {
        if (out != null) {
            out.close();
            out = null;
        }
    }

    public boolean isOpen() { return out != null; }
}

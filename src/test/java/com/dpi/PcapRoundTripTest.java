package com.dpi;

import static org.junit.Assert.*;

import com.dpi.pcap.PcapReader;
import com.dpi.pcap.PcapWriter;
import com.dpi.pcap.RawPacket;
import java.io.File;
import org.junit.Test;

public class PcapRoundTripTest {

    private RawPacket makePacket(long sec, long usec, int size, int fill) {
        RawPacket p = new RawPacket();
        p.header.tsSec = sec;
        p.header.tsUsec = usec;
        p.data = new byte[size];
        for (int i = 0; i < size; i++) p.data[i] = (byte) (fill + i);
        return p;
    }

    @Test
    public void packetsReadBackMatchWhatWasWritten() throws Exception {
        File f = File.createTempFile("roundtrip", ".pcap");
        f.deleteOnExit();

        RawPacket a = makePacket(1700000000L, 123456L, 54, 1);
        RawPacket b = makePacket(1700000001L, 999999L, 100, 50);

        PcapWriter writer = new PcapWriter();
        assertTrue(writer.open(f.getAbsolutePath()));
        writer.writePacket(a);
        writer.writePacket(b);
        writer.close();

        PcapReader reader = new PcapReader();
        assertTrue(reader.open(f.getAbsolutePath()));
        assertFalse(reader.needsByteSwap());

        RawPacket r = new RawPacket();

        assertTrue(reader.readNextPacket(r));
        assertEquals(1700000000L, r.header.tsSec);
        assertEquals(123456L, r.header.tsUsec);
        assertArrayEquals(a.data, r.data);

        assertTrue(reader.readNextPacket(r));
        assertEquals(1700000001L, r.header.tsSec);
        assertEquals(999999L, r.header.tsUsec);
        assertArrayEquals(b.data, r.data);

        assertFalse(reader.readNextPacket(r));   // end of file
        reader.close();
    }

    @Test
    public void emptyCaptureIsStillAValidPcap() throws Exception {
        File f = File.createTempFile("empty", ".pcap");
        f.deleteOnExit();

        PcapWriter writer = new PcapWriter();
        writer.open(f.getAbsolutePath());
        writer.close();

        PcapReader reader = new PcapReader();
        assertTrue(reader.open(f.getAbsolutePath()));
        assertFalse(reader.readNextPacket(new RawPacket()));
        reader.close();
    }
}

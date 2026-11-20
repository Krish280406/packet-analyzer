package com.dpi;

import static org.junit.Assert.*;

import com.dpi.pcap.PcapWriter;
import com.dpi.pcap.RawPacket;
import java.io.File;
import org.junit.Test;

public class PcapWriterTest {

    @Test
    public void writtenFileHasCorrectSize() throws Exception {
        File f = File.createTempFile("out", ".pcap");
        f.deleteOnExit();

        RawPacket p1 = new RawPacket();
        p1.data = new byte[54];
        RawPacket p2 = new RawPacket();
        p2.data = new byte[100];

        PcapWriter writer = new PcapWriter();
        assertTrue(writer.open(f.getAbsolutePath()));
        writer.writePacket(p1);
        writer.writePacket(p2);
        writer.close();

        // 24 (global header) + 2 * 16 (packet headers) + 54 + 100
        assertEquals(24 + 16 + 54 + 16 + 100, f.length());
    }
}

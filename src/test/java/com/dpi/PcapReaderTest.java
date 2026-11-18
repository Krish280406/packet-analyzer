package com.dpi;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

import com.dpi.pcap.PcapReader;
import com.dpi.pcap.RawPacket;
import java.io.File;
import java.nio.file.Files;
import org.junit.Test;

public class PcapReaderTest {

    @Test
    public void readsAllPacketsFromGeneratedFile() throws Exception {
        assumeTrue(new File("test_dpi.pcap").exists());

        PcapReader reader = new PcapReader();
        assertTrue(reader.open("test_dpi.pcap"));
        RawPacket pkt = new RawPacket();
        int count = 0;
        long bytes = 0;
        while (reader.readNextPacket(pkt)) {
            count++;
            bytes += pkt.data.length;
        }
        reader.close();

        assertEquals(77, count);
        assertEquals(5738, bytes);
    }

    @Test
    public void rejectsFileWithBadMagicNumber() throws Exception {
        File f = File.createTempFile("bad", ".pcap");
        f.deleteOnExit();
        Files.write(f.toPath(), new byte[24]);

        PcapReader reader = new PcapReader();
        assertFalse(reader.open(f.getAbsolutePath()));
    }
}

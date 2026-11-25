package com.dpi;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

import com.dpi.engine.MultiThreadedDPIEngine;
import com.dpi.parser.PacketParser;
import com.dpi.parser.ParsedPacket;
import com.dpi.pcap.PcapReader;
import com.dpi.pcap.RawPacket;
import java.io.File;
import org.junit.Test;

public class MultiThreadOutputTest {

    // returns {packetCount, packetsThatParse}
    private int[] runEngine(String rule, String value, int threads) throws Exception {
        assumeTrue(new File("test_dpi.pcap").exists());

        File out = File.createTempFile("mt_out", ".pcap");
        out.deleteOnExit();

        MultiThreadedDPIEngine engine =
            new MultiThreadedDPIEngine("test_dpi.pcap", out.getAbsolutePath(), threads);
        if (rule != null) {
            engine.addBlockRule(rule, value);
        }
        assertTrue(engine.process());

        PcapReader reader = new PcapReader();
        assertTrue(reader.open(out.getAbsolutePath()));
        RawPacket raw = new RawPacket();
        int count = 0, parsed = 0;
        while (reader.readNextPacket(raw)) {
            count++;
            if (PacketParser.parse(raw, new ParsedPacket())) parsed++;
        }
        reader.close();
        return new int[] {count, parsed};
    }

    @Test
    public void noRulesKeepsAll77PacketsAndTheyAllParse() throws Exception {
        int[] r = runEngine(null, null, 4);
        assertEquals(77, r[0]);
        assertEquals(77, r[1]);
    }

    @Test
    public void outputIsNotCorruptWithManyThreads() throws Exception {
        int[] r = runEngine(null, null, 8);
        assertEquals(77, r[0]);
        assertEquals(77, r[1]);
    }

    @Test
    public void ipRuleDoesNothingInMultiThreadMode() throws Exception {
        // KNOWN BUG: the worker packs IPs big-endian, so --block-ip never matches here.
        int[] r = runEngine("ip", "192.168.1.50", 4);
        assertEquals(77, r[0]);
    }
}

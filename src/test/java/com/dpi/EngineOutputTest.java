package com.dpi;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

import com.dpi.engine.DPIEngine;
import com.dpi.extractor.SNIExtractor;
import com.dpi.parser.PacketParser;
import com.dpi.parser.ParsedPacket;
import com.dpi.pcap.PcapReader;
import com.dpi.pcap.RawPacket;
import java.io.File;
import java.util.Optional;
import org.junit.Test;

public class EngineOutputTest {

    private int runEngine(String rule, String value, boolean[] youtubeHelloFound) throws Exception {
        assumeTrue(new File("test_dpi.pcap").exists());

        File out = File.createTempFile("engine_out", ".pcap");
        out.deleteOnExit();

        DPIEngine engine = new DPIEngine("test_dpi.pcap", out.getAbsolutePath());
        if (rule != null) {
            engine.addBlockRule(rule, value);
        }
        assertTrue(engine.process());

        PcapReader reader = new PcapReader();
        assertTrue(reader.open(out.getAbsolutePath()));
        RawPacket raw = new RawPacket();
        int count = 0;
        while (reader.readNextPacket(raw)) {
            count++;
            ParsedPacket p = new ParsedPacket();
            if (PacketParser.parse(raw, p) && p.destPort == 443 && p.payloadLength > 5) {
                Optional<String> sni = SNIExtractor.extract(p.payloadData, 0, p.payloadLength);
                if (sni.isPresent() && sni.get().contains("youtube")) {
                    youtubeHelloFound[0] = true;
                }
            }
        }
        reader.close();
        return count;
    }

    @Test
    public void noRulesKeepsAll77Packets() throws Exception {
        assertEquals(77, runEngine(null, null, new boolean[1]));
    }

    @Test
    public void blockingYouTubeRemovesOnlyTheClientHello() throws Exception {
        boolean[] found = new boolean[1];
        assertEquals(76, runEngine("app", "YouTube", found));
        assertFalse(found[0]);
    }

    @Test
    public void blockingSourceIpRemovesItsFivePackets() throws Exception {
        assertEquals(72, runEngine("ip", "192.168.1.50", new boolean[1]));
    }
}

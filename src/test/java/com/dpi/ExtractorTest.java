package com.dpi;

import static org.junit.Assert.*;

import com.dpi.extractor.DNSExtractor;
import com.dpi.extractor.HTTPHostExtractor;
import com.dpi.extractor.SNIExtractor;
import java.util.Optional;
import org.junit.Test;

public class ExtractorTest {

    // ---------- SNI ----------

    @Test
    public void sniIsFoundInClientHello() {
        byte[] hello = TestPackets.clientHello("www.youtube.com");
        Optional<String> sni = SNIExtractor.extract(hello, 0, hello.length);
        assertEquals(Optional.of("www.youtube.com"), sni);
    }

    @Test
    public void sniIsEmptyForNonTlsBytes() {
        byte[] junk = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        assertFalse(SNIExtractor.extract(junk, 0, junk.length).isPresent());
        byte[] http = "GET / HTTP/1.1\r\n\r\n".getBytes();
        assertFalse(SNIExtractor.extract(http, 0, http.length).isPresent());
    }

    @Test
    public void sniIsEmptyWhenClientHelloIsCutOff() {
        byte[] hello = TestPackets.clientHello("www.youtube.com");
        int half = hello.length / 2;
        assertFalse(SNIExtractor.extract(hello, 0, half).isPresent());
    }

    // ---------- HTTP Host ----------

    @Test
    public void httpHostIsFoundAndPortIsRemoved() {
        byte[] req = "GET / HTTP/1.1\r\nHost: Example.com:8080\r\nAccept: */*\r\n\r\n".getBytes();
        assertEquals(Optional.of("Example.com"), HTTPHostExtractor.extract(req, 0, req.length));
    }

    @Test
    public void httpHostIsEmptyWithoutHostOrNonHttp() {
        byte[] noHost = "GET / HTTP/1.1\r\nAccept: */*\r\n\r\n".getBytes();
        assertFalse(HTTPHostExtractor.extract(noHost, 0, noHost.length).isPresent());
        byte[] tls = TestPackets.clientHello("www.google.com");
        assertFalse(HTTPHostExtractor.extract(tls, 0, tls.length).isPresent());
    }

    // ---------- DNS ----------

    @Test
    public void dnsQueryNameIsFound() {
        byte[] q = TestPackets.dnsQuery("www.youtube.com");
        assertEquals(Optional.of("www.youtube.com"), DNSExtractor.extractQuery(q, 0, q.length));
    }

    @Test
    public void dnsResponsesAreIgnored() {
        byte[] q = TestPackets.dnsQuery("www.youtube.com");
        q[2] = (byte) 0x81;   // response bit set
        assertFalse(DNSExtractor.extractQuery(q, 0, q.length).isPresent());
    }

    @Test
    public void dnsTooShortIsIgnored() {
        byte[] tiny = new byte[8];
        assertFalse(DNSExtractor.extractQuery(tiny, 0, tiny.length).isPresent());
    }
}

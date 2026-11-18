package com.dpi;

import static org.junit.Assert.*;

import com.dpi.engine.RuleManager;
import com.dpi.types.AppType;
import com.dpi.types.FiveTuple;
import java.util.HashMap;
import java.util.Map;
import org.junit.Test;

public class RulesAndTypesTest {

    // 192.168.1.50 packed little-endian (what RuleManager and DPIEngine use)
    private static final long IP_LITTLE = 192L | (168L << 8) | (1L << 16) | (50L << 24);
    // the same address packed big-endian (what FastPathThread uses)
    private static final long IP_BIG = (192L << 24) | (168L << 16) | (1L << 8) | 50L;

    // ---------- RuleManager ----------

    @Test
    public void appRuleBlocksOnlyThatApp() {
        RuleManager rm = new RuleManager();
        rm.addRule("app", "YouTube");
        assertTrue(rm.isBlocked(0, AppType.YOUTUBE, "www.youtube.com"));
        assertFalse(rm.isBlocked(0, AppType.FACEBOOK, "www.facebook.com"));
    }

    @Test
    public void domainRuleMatchesBySubstring() {
        RuleManager rm = new RuleManager();
        rm.addRule("domain", "facebook.com");
        assertTrue(rm.isBlocked(0, AppType.FACEBOOK, "www.facebook.com"));
        // KNOWN BUG: substring match also blocks look-alike names.
        assertTrue(rm.isBlocked(0, AppType.HTTPS, "notfacebook.com"));
        assertFalse(rm.isBlocked(0, AppType.GOOGLE, "www.google.com"));
    }

    @Test
    public void ipRuleMatchesLittleEndianValue() {
        RuleManager rm = new RuleManager();
        rm.addRule("ip", "192.168.1.50");
        assertTrue(rm.isBlocked(IP_LITTLE, AppType.UNKNOWN, ""));
    }

    @Test
    public void ipRuleDoesNotMatchBigEndianValue() {
        // KNOWN BUG: FastPathThread packs big-endian, so --block-ip never matches in multi-thread mode.
        RuleManager rm = new RuleManager();
        rm.addRule("ip", "192.168.1.50");
        assertFalse(rm.isBlocked(IP_BIG, AppType.UNKNOWN, ""));
    }

    @Test(expected = IllegalArgumentException.class)
    public void unknownAppNameThrows() {
        // KNOWN BUG: an unknown app name crashes instead of printing a friendly message.
        new RuleManager().addRule("app", "Twitch");
    }

    // ---------- AppType ----------

    @Test
    public void fromSniMapsKnownSites() {
        assertEquals(AppType.YOUTUBE, AppType.fromSni("www.youtube.com"));
        assertEquals(AppType.YOUTUBE, AppType.fromSni("youtube.googleapis.com"));
        assertEquals(AppType.GOOGLE, AppType.fromSni("www.google.com"));
        assertEquals(AppType.TWITTER, AppType.fromSni("twitter.com"));
    }

    @Test
    public void fromSniFallbacks() {
        assertEquals(AppType.UNKNOWN, AppType.fromSni(null));
        assertEquals(AppType.UNKNOWN, AppType.fromSni(""));
        assertEquals(AppType.HTTPS, AppType.fromSni("example.org"));
    }

    @Test
    public void fromSniFalsePositive() {
        // KNOWN BUG: substring matching labels pineapple.com as Apple.
        assertEquals(AppType.APPLE, AppType.fromSni("pineapple.com"));
    }

    // ---------- FiveTuple ----------

    @Test
    public void fiveTupleWorksAsMapKeyAndReverseDiffers() {
        FiveTuple a = new FiveTuple(1, 2, 3, 4, (byte) 6);
        FiveTuple b = new FiveTuple(1, 2, 3, 4, (byte) 6);
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
        assertNotEquals(a, a.reverse());

        Map<FiveTuple, String> map = new HashMap<>();
        map.put(a, "flow");
        assertEquals("flow", map.get(b));
    }
}

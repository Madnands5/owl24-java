package dev.owl24.apm;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.AfterEach;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Task 12 (todolist.md) named PII-masking as "a good first real test
 * target" for owl24-js; this is the same ported suite for owl24-java,
 * added 2026-08-23 alongside the JUnit5/Surefire wiring itself (there was
 * no test framework at all in this module before this).
 */
class MaskingTest {

    @AfterEach
    void resetMaskingConfig() {
        // configureMasking mutates static state shared across the whole
        // JVM/test run - reset after each test so one test's custom
        // maskFields/hostname suffixes never leak into another's.
        Masking.configureMasking(null, null);
    }

    @Test
    void luhnChecksum() {
        assertTrue(Masking.luhnValid("4111111111111111"), "real Visa test number");
        assertFalse(Masking.luhnValid("1234567890123456"), "random non-Luhn digit run");
    }

    @Test
    void cardMasking() {
        assertEquals("card: 411111******1111", Masking.maskSensitiveData("card: 4111111111111111"));
        assertEquals("550000******5559", Masking.maskSensitiveData("5500005555555559"));
        assertEquals("378282*****0005", Masking.maskSensitiveData("378282246310005"));
        assertEquals("id: 1234567890123456", Masking.maskSensitiveData("id: 1234567890123456"),
            "a 16-digit run that fails Luhn is left untouched - fixes the old bare-regex over-matching bug");
    }

    @Test
    void secrets() {
        assertEquals("key=[SECRET_MASKED]", Masking.maskSensitiveData("key=AKIAIOSFODNN7EXAMPLE"));
        assertEquals("token [SECRET_MASKED]", Masking.maskSensitiveData("token ghp_" + "a".repeat(36)));
        assertEquals("[SECRET_MASKED]", Masking.maskSensitiveData("xoxb-1234567890-abcdefg"));
        assertEquals("[SECRET_MASKED]", Masking.maskSensitiveData("sk_live_" + "a".repeat(24)));
        assertEquals("[SECRET_MASKED]",
            Masking.maskSensitiveData("-----BEGIN RSA PRIVATE KEY-----\nABC123\n-----END RSA PRIVATE KEY-----"));
    }

    @Test
    void tightenedJwtBearer() {
        String realJwt = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abc123XYZ_-";
        assertEquals("[TOKEN_MASKED]", Masking.maskSensitiveData(realJwt),
            "a real JWT including one ending in '-', the boundary bug this replaced");
        assertEquals("Authorization: Bearer sometoken123",
            Masking.maskSensitiveData("Authorization: Bearer sometoken123"),
            "the old loose regex over-matched this - a non-JWT Bearer token must be left untouched");
    }

    @Test
    void fieldNameKeywordCatchAll() {
        assertTrue(Masking.isSensitiveFieldName("user_password"));
        assertTrue(Masking.isSensitiveFieldName("stripe_api_key"));
        assertFalse(Masking.isSensitiveFieldName("service_name"));
    }

    @Test
    void ibanMod97() {
        String realIban = "DE89370400440532013000";
        assertTrue(Masking.ibanValid(realIban));
        assertFalse(Masking.ibanValid("DE00000000000000000000"), "IBAN-shaped but invalid checksum");
        String masked = Masking.maskSensitiveData(realIban);
        assertEquals("DE", masked.substring(0, 2), "country code preserved");
        assertTrue(Masking.ibanValid(masked), "masked IBAN still round-trips as structurally valid");
        assertEquals("ZZ00000000000000000000", Masking.maskSensitiveData("ZZ00000000000000000000"));
    }

    @Test
    void usRoutingNumbers() {
        assertTrue(Masking.routingValid("011401533"), "real Bank of America routing number");
        assertFalse(Masking.routingValid("123456789"));
        assertEquals("routing [ROUTING_MASKED]", Masking.maskSensitiveData("routing 011401533"));
        assertEquals("id 123456789", Masking.maskSensitiveData("id 123456789"));
    }

    @Test
    void ipTruncation() {
        assertEquals("client 203.0.113.0 connected", Masking.maskSensitiveData("client 203.0.113.42 connected"));
        assertEquals("2001:0db8:85a3:0:0:0:0:0",
            Masking.maskSensitiveData("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
    }

    @Test
    void rfc1918Detection() {
        assertTrue(Masking.isPrivateIPv4("10.1.2.3"));
        assertTrue(Masking.isPrivateIPv4("172.20.5.5"), "inside 172.16.0.0/12");
        assertFalse(Masking.isPrivateIPv4("172.32.5.5"), "outside 172.16.0.0/12");
        assertTrue(Masking.isPrivateIPv4("192.168.1.1"));
        assertTrue(Masking.isPrivateIPv4("127.0.0.1"), "loopback");
        assertFalse(Masking.isPrivateIPv4("8.8.8.8"), "public DNS");
    }

    @Test
    void internalHostnameSuffixes() {
        assertEquals("connecting to [HOSTNAME_MASKED] now",
            Masking.maskSensitiveData("connecting to db-primary.internal now"));
        assertEquals("[HOSTNAME_MASKED]", Masking.maskSensitiveData("redis.default.svc.cluster.local"));
        assertEquals("example.com", Masking.maskSensitiveData("example.com"), "a non-denylisted domain is untouched");
    }

    @Test
    void configurableFieldNamesAndHostnameSuffixes() {
        Masking.configureMasking(List.of("*internal_customer_id*", "pricing.*"), List.of(".mycorp.io"));
        assertTrue(Masking.isSensitiveFieldName("internal_customer_id"));
        assertTrue(Masking.isSensitiveFieldName("pricing.tier"));
        assertFalse(Masking.isSensitiveFieldName("unrelated_field"));
        assertTrue(Masking.isSensitiveFieldName("password"), "defaults still apply alongside custom patterns");
        assertEquals("[HOSTNAME_MASKED]", Masking.maskSensitiveData("worker-3.mycorp.io"));
        assertEquals("[HOSTNAME_MASKED]", Masking.maskSensitiveData("db.internal"), "default suffix still applies too");
    }

    @Test
    void emailMasking() {
        assertEquals("contact me at [EMAIL_MASKED]", Masking.maskSensitiveData("contact me at a@b.com"));
    }
}

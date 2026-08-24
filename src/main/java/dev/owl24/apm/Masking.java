package dev.owl24.apm;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Task 8 (todolist.md), expanded 2026-08-23 from the original 4 bare
 * regexes. Faithful port of owl24-js's masking.js (the reference
 * implementation - see that file's own header for the full research/
 * rationale behind every category here) - same detection categories, same
 * masking formats, same tests translated to this language.
 */
final class Masking {
    private Masking() {}

    // --- PCI-DSS payment cards -------------------------------------------
    private static final Pattern CARD_CANDIDATE_RE = Pattern.compile("\\b(?:\\d[ -]?){13,19}\\b");
    private static final Pattern CARD_BRAND_RE = Pattern.compile(
        "^(4\\d{12}(?:\\d{3})?|5[1-5]\\d{14}|2(?:22[1-9]|2[3-9]\\d|[3-6]\\d{2}|7[01]\\d|720)\\d{12}|3[47]\\d{13}|6(?:011|5\\d{2})\\d{12})$");

    static boolean luhnValid(String digits) {
        int sum = 0;
        boolean alternate = false;
        for (int i = digits.length() - 1; i >= 0; i--) {
            int n = digits.charAt(i) - '0';
            if (alternate) {
                n *= 2;
                if (n > 9) n -= 9;
            }
            sum += n;
            alternate = !alternate;
        }
        return sum % 10 == 0;
    }

    // PCI DSS "truncation" convention: first 6 + last 4 visible, middle masked.
    private static String maskCard(String match) {
        String digits = match.replaceAll("[ -]", "");
        if (!CARD_BRAND_RE.matcher(digits).matches() || !luhnValid(digits)) return match;
        return digits.substring(0, 6) + "*".repeat(digits.length() - 10) + digits.substring(digits.length() - 4);
    }

    // --- Secrets & credentials --------------------------------------------
    // Vendor-prefixed formats ported from gitleaks' config/gitleaks.toml (MIT).
    private static final Pattern[] SECRET_PATTERNS = {
        Pattern.compile("\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b"),
        Pattern.compile("\\bgh[pousr]_[A-Za-z0-9]{36,}\\b"),
        Pattern.compile("\\bgithub_pat_[A-Za-z0-9_]{22,}\\b"),
        // Lookahead, not \b, at the end - the token body's character class
        // includes '-', a non-word char, so a token ending in '-' would
        // fail a trailing \b (the real bug found and fixed in the JS
        // reference implementation's own Bearer/JWT regex, below).
        Pattern.compile("\\bxox[baprs]-[A-Za-z0-9-]{10,}(?![A-Za-z0-9-])"),
        Pattern.compile("\\bsk_(?:live|test)_[A-Za-z0-9]{16,}\\b"),
        Pattern.compile("-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\\s\\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"),
    };

    // Tightened from "Bearer + anything JWT-shaped" to the real structure
    // (eyJ prefix + 3 dot-separated base64url segments).
    private static final Pattern BEARER_JWT_RE =
        Pattern.compile("\\bBearer\\s+eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+(?![A-Za-z0-9_-])");

    // --- Financial / banking -----------------------------------------------
    private static final Pattern IBAN_CANDIDATE_RE = Pattern.compile("\\b[A-Z]{2}\\d{2}[A-Z0-9]{11,30}\\b");

    private static int mod97(String numeric) {
        int remainder = 0;
        for (int i = 0; i < numeric.length(); i++) {
            remainder = (remainder * 10 + (numeric.charAt(i) - '0')) % 97;
        }
        return remainder;
    }

    private static String ibanNumeric(String iban) {
        String rearranged = iban.substring(4) + iban.substring(0, 4);
        StringBuilder sb = new StringBuilder();
        for (char c : rearranged.toCharArray()) {
            sb.append(c >= 'A' && c <= 'Z' ? String.valueOf((int) c - 55) : String.valueOf(c));
        }
        return sb.toString();
    }

    static boolean ibanValid(String iban) {
        return mod97(ibanNumeric(iban)) == 1;
    }

    // Masks by preserving the country code and regenerating a valid
    // checksum on an all-zero masked body, so the result still round-trips
    // as a structurally valid IBAN (dlpx-core's IBAN masking pattern).
    private static String maskIban(String match) {
        String iban = match.toUpperCase();
        if (!ibanValid(iban)) return match;
        String country = iban.substring(0, 2);
        String bban = "0".repeat(iban.length() - 4);
        int remainder = mod97(ibanNumeric(country + "00" + bban));
        String checkDigits = String.format("%02d", 98 - remainder);
        return country + checkDigits + bban;
    }

    // US routing numbers: 9 digits, weighted (3,7,1 repeating) checksum.
    private static final Pattern ROUTING_CANDIDATE_RE = Pattern.compile("\\b\\d{9}\\b");
    private static final int[] ROUTING_WEIGHTS = {3, 7, 1, 3, 7, 1, 3, 7, 1};

    static boolean routingValid(String digits) {
        int sum = 0;
        for (int i = 0; i < 9; i++) sum += (digits.charAt(i) - '0') * ROUTING_WEIGHTS[i];
        return sum % 10 == 0;
    }

    // --- Location / geolocation ---------------------------------------------
    // IPv4: zero the last octet. IPv6: keep the first 48 bits, zero the
    // rest - both match Google Analytics' old anonymizeIp.
    private static final Pattern IPV4_RE = Pattern.compile("\\b(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\b");
    private static final Pattern IPV6_RE = Pattern.compile("\\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\\b");

    // --- Internal network topology -------------------------------------------
    // RFC1918 (+loopback/link-local) via real numeric subnet math, not regex.
    private static final Object[][] PRIVATE_IPV4_RANGES = {
        {"10.0.0.0", 8}, {"172.16.0.0", 12}, {"192.168.0.0", 16}, {"127.0.0.0", 8}, {"169.254.0.0", 16},
    };

    private static long ipv4ToLong(String ip) {
        long result = 0;
        for (String octet : ip.split("\\.")) result = (result << 8) + Long.parseLong(octet);
        return result;
    }

    static boolean isPrivateIPv4(String ip) {
        long ipLong = ipv4ToLong(ip);
        for (Object[] range : PRIVATE_IPV4_RANGES) {
            int bits = (Integer) range[1];
            long mask = bits == 0 ? 0 : (0xFFFFFFFFL << (32 - bits)) & 0xFFFFFFFFL;
            if ((ipLong & mask) == (ipv4ToLong((String) range[0]) & mask)) return true;
        }
        return false;
    }

    // Hostnames/internal DNS/cluster names have no universal spec - a
    // small default suffix denylist, extended via configureMasking().
    private static final List<String> DEFAULT_INTERNAL_HOSTNAME_SUFFIXES =
        List.of(".internal", ".svc.cluster.local", ".corp");

    private static List<Pattern> buildHostnameSuffixPatterns(List<String> suffixes) {
        List<Pattern> patterns = new ArrayList<>();
        for (String suffix : suffixes) {
            patterns.add(Pattern.compile("\\b[\\w-]+(?:\\.[\\w-]+)*" + Pattern.quote(suffix) + "\\b", Pattern.CASE_INSENSITIVE));
        }
        return patterns;
    }

    // --- Customer-configurable field-name allow/deny list --------------------
    // Denylist-default (mask only what's configured, everything else passes
    // through), not allowlist-default - matches owl24-js's decision: owl24's
    // "one line of code, 5-minute setup" pitch doesn't work if a customer
    // has to enumerate every safe field up front.
    private static final Pattern[] DEFAULT_SENSITIVE_FIELD_NAME_PATTERNS = {
        Pattern.compile("password", Pattern.CASE_INSENSITIVE),
        Pattern.compile("secret", Pattern.CASE_INSENSITIVE),
        Pattern.compile("token", Pattern.CASE_INSENSITIVE),
        Pattern.compile("api[_-]?key", Pattern.CASE_INSENSITIVE),
        Pattern.compile("credential", Pattern.CASE_INSENSITIVE),
        Pattern.compile("authorization", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bssn\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("social[_-]?security", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bpin\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bbalance\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("account[_-]?number", Pattern.CASE_INSENSITIVE),
        Pattern.compile("routing[_-]?number", Pattern.CASE_INSENSITIVE),
        Pattern.compile("credit[_-]?score", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bdob\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("date[_-]?of[_-]?birth", Pattern.CASE_INSENSITIVE),
    };

    private static volatile List<Pattern> customFieldNamePatterns = List.of();
    private static volatile List<Pattern> hostnameSuffixPatterns = buildHostnameSuffixPatterns(DEFAULT_INTERNAL_HOSTNAME_SUFFIXES);

    private static Pattern compileWildcard(String pattern) {
        String[] parts = pattern.split("\\*", -1);
        StringBuilder sb = new StringBuilder("^");
        for (int i = 0; i < parts.length; i++) {
            if (i > 0) sb.append(".*");
            sb.append(Pattern.quote(parts[i]));
        }
        sb.append("$");
        return Pattern.compile(sb.toString(), Pattern.CASE_INSENSITIVE);
    }

    /**
     * Lets a customer extend (not replace) the default sensitive-field-name
     * list and the internal-hostname suffix list. maskFields accepts exact
     * names or '*'-wildcard patterns (e.g. "*api_key*", "pricing.*",
     * "internal_customer_id"). Call before Owl24.init(), or any time
     * afterward to change behavior live.
     */
    static void configureMasking(List<String> maskFields, List<String> internalHostnameSuffixes) {
        List<Pattern> compiled = new ArrayList<>();
        if (maskFields != null) for (String f : maskFields) compiled.add(compileWildcard(f));
        customFieldNamePatterns = compiled;

        List<String> suffixes = new ArrayList<>(DEFAULT_INTERNAL_HOSTNAME_SUFFIXES);
        if (internalHostnameSuffixes != null) suffixes.addAll(internalHostnameSuffixes);
        hostnameSuffixPatterns = buildHostnameSuffixPatterns(suffixes);
    }

    /** True if `name` (an attribute/log-field name) should be masked wholesale, regardless of shape. */
    static boolean isSensitiveFieldName(String name) {
        for (Pattern p : DEFAULT_SENSITIVE_FIELD_NAME_PATTERNS) if (p.matcher(name).find()) return true;
        for (Pattern p : customFieldNamePatterns) if (p.matcher(name).matches()) return true;
        return false;
    }

    // Order matters (see owl24-js's masking.js for the full story of why):
    // vendor-prefixed/checksum-gated patterns must run BEFORE the generic
    // phone pattern, or phone's boundary-bounded-but-still-generic digit
    // match can claim a 10-digit body out of a hyphen-delimited secret
    // token before the secret pattern gets a chance to match the whole span.
    private static final Pattern PHONE_RE =
        Pattern.compile("\\b(\\+?\\d{1,3}[-.\\s]?)?\\(?\\d{3}\\)?[-.\\s]?\\d{3}[-.\\s]?\\d{4}\\b");

    /** Value-based masking - runs regardless of field name. */
    static String maskSensitiveData(String text) {
        if (text == null) return null;

        String masked = text.replaceAll("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}", "[EMAIL_MASKED]");

        for (Pattern p : SECRET_PATTERNS) {
            masked = p.matcher(masked).replaceAll("[SECRET_MASKED]");
        }

        masked = BEARER_JWT_RE.matcher(masked).replaceAll("[TOKEN_MASKED]");
        masked = replaceWithFunction(masked, CARD_CANDIDATE_RE, Masking::maskCard);
        masked = replaceWithFunction(masked, IBAN_CANDIDATE_RE, Masking::maskIban);
        masked = replaceWithFunction(masked, ROUTING_CANDIDATE_RE, (m) -> routingValid(m) ? "[ROUTING_MASKED]" : m);
        masked = replaceWithFunction(masked, IPV4_RE, Masking::truncateIpv4Match);
        masked = replaceWithFunction(masked, IPV6_RE, Masking::truncateIpv6Match);

        for (Pattern p : hostnameSuffixPatterns) {
            masked = p.matcher(masked).replaceAll("[HOSTNAME_MASKED]");
        }

        masked = PHONE_RE.matcher(masked).replaceAll("[PHONE_MASKED]");

        return masked;
    }

    private static String truncateIpv4Match(String match) {
        String[] octets = match.split("\\.");
        for (String o : octets) if (Integer.parseInt(o) > 255) return match;
        return octets[0] + "." + octets[1] + "." + octets[2] + ".0";
    }

    private static String truncateIpv6Match(String match) {
        String[] groups = match.split(":");
        return groups[0] + ":" + groups[1] + ":" + groups[2] + ":0:0:0:0:0";
    }

    private interface MatchFn {
        String apply(String match);
    }

    // java.util.regex has no direct "replace with a function of the match"
    // (unlike JS/Python's String.replace(regex, fn)) - Matcher.appendReplacement
    // does the same job manually.
    private static String replaceWithFunction(String text, Pattern pattern, MatchFn fn) {
        Matcher matcher = pattern.matcher(text);
        StringBuilder sb = new StringBuilder();
        while (matcher.find()) {
            matcher.appendReplacement(sb, Matcher.quoteReplacement(fn.apply(matcher.group())));
        }
        matcher.appendTail(sb);
        return sb.toString();
    }
}

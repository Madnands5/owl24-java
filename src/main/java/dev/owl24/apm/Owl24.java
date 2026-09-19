package dev.owl24.apm;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.common.AttributesBuilder;
import io.opentelemetry.api.logs.Logger;
import io.opentelemetry.api.logs.Severity;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanContext;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.exporter.otlp.http.logs.OtlpHttpLogRecordExporter;
import io.opentelemetry.exporter.otlp.http.metrics.OtlpHttpMetricExporter;
import io.opentelemetry.exporter.otlp.http.trace.OtlpHttpSpanExporter;
import io.opentelemetry.instrumentation.jdbc.datasource.JdbcTelemetry;
import io.opentelemetry.instrumentation.runtimemetrics.java8.Classes;
import io.opentelemetry.instrumentation.runtimemetrics.java8.Cpu;
import io.opentelemetry.instrumentation.runtimemetrics.java8.GarbageCollector;
import io.opentelemetry.instrumentation.runtimemetrics.java8.MemoryPools;
import io.opentelemetry.instrumentation.runtimemetrics.java8.Threads;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.common.CompletableResultCode;
import io.opentelemetry.sdk.common.InstrumentationLibraryInfo;
import io.opentelemetry.sdk.common.InstrumentationScopeInfo;
import io.opentelemetry.sdk.logs.SdkLoggerProvider;
import io.opentelemetry.sdk.logs.export.BatchLogRecordProcessor;
import io.opentelemetry.sdk.metrics.SdkMeterProvider;
import io.opentelemetry.sdk.metrics.export.PeriodicMetricReader;
import io.opentelemetry.sdk.resources.Resource;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.sdk.trace.data.EventData;
import io.opentelemetry.sdk.trace.data.LinkData;
import io.opentelemetry.sdk.trace.data.SpanData;
import io.opentelemetry.sdk.trace.data.StatusData;
import io.opentelemetry.sdk.trace.export.BatchSpanProcessor;
import io.opentelemetry.sdk.trace.export.SpanExporter;

import javax.sql.DataSource;

import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.LogRecord;
import java.util.logging.SimpleFormatter;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class Owl24 {
    private static OpenTelemetrySdk openTelemetrySdk;
    private static Owl24StatusTracker statusTracker;
    // Package-private (not private): Owl24LogbackAppender, in the same
    // package, reuses this rather than duplicating the emit/mask pipeline.
    static Logger otelLogger;
    // Close handles returned by each runtime-metrics registerObservers() call
    // below - each one is a live JMX listener/callback registration, so
    // shutdown() must close them or they'd keep the JVM's metric-collection
    // hooks (and a reference to the now-shutdown SDK) alive indefinitely.
    private static List<AutoCloseable> runtimeMetricsHandles = new ArrayList<>();
    private static final ObjectMapper objectMapper = new ObjectMapper();
    // Task H (competitive-roadmap.md) - set once at the end of init()'s core
    // pipeline setup; trackEvent() below reads this rather than requiring a
    // separate init-time argument.
    private static volatile EventIngestConfig eventIngestConfig;

    private static final class EventIngestConfig {
        final String ingestBaseUrl;
        final String apiKey;
        final String userEmail;
        final String serviceName;

        EventIngestConfig(String ingestBaseUrl, String apiKey, String userEmail, String serviceName) {
            this.ingestBaseUrl = ingestBaseUrl;
            this.apiKey = apiKey;
            this.userEmail = userEmail;
            this.serviceName = serviceName;
        }
    }

    // Must run before ORIGINAL_ERR captures System.err below, and before any
    // print statement anywhere in this class - PrintStream's platform
    // default charset (e.g. Windows' cp1252) can't encode this SDK's emoji
    // output, silently corrupting it to "?" instead of throwing (verified
    // live running the demo server on Windows). Forcing UTF-8 fixes that,
    // consistent with owl24-py's equivalent fix for the same class of bug.
    static {
        try {
            System.setOut(new PrintStream(new FileOutputStream(FileDescriptor.out), true, StandardCharsets.UTF_8));
            System.setErr(new PrintStream(new FileOutputStream(FileDescriptor.err), true, StandardCharsets.UTF_8));
        } catch (Exception e) {
            // Best-effort only - fall back to the platform default if this itself fails.
        }
    }

    // Captured once, before setupConsoleBridge() ever wraps System.out/err,
    // so the crash handler can print diagnostics without looping back
    // through the bridge (which would re-emit each printed line as its own
    // log event - noisy, and structurally the same kind of feedback-loop
    // risk that turned out to be a real, verified hang in owl24-py when the
    // bridge's target was a logging framework instead of raw stdout/stderr).
    private static final PrintStream ORIGINAL_ERR = System.err;

    static {
        objectMapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
    }

    // Task 8 (todolist.md), expanded 2026-08-23 - see Masking.java for the
    // full detection categories (PCI-DSS cards with Luhn validation,
    // gitleaks-derived secret prefixes, IBAN/MOD-97, US routing numbers, IP
    // truncation, RFC1918 detection, internal hostname suffixes) and the
    // customer-configurable field-name mechanism that backs proprietary/
    // business-sensitive data, which has no pattern of its own. Kept as a
    // package-private delegate (not removed) since other classes in this
    // package call it by this name.
    static String maskSensitiveData(String text) {
        return Masking.maskSensitiveData(text);
    }

    /**
     * Lets a customer extend (not replace) the default sensitive-field-name
     * list and the internal-hostname suffix list. maskFields accepts exact
     * names or '*'-wildcard patterns (e.g. "*api_key*", "pricing.*",
     * "internal_customer_id"). Call before init(), or any time afterward to
     * change behavior live - unlike the constructor-style init() overloads,
     * this doesn't need to grow the parameter list for every new option.
     */
    public static void configureMasking(java.util.List<String> maskFields, java.util.List<String> internalHostnameSuffixes) {
        Masking.configureMasking(maskFields, internalHostnameSuffixes);
    }

    static String safeSerialize(Object msg) {
        if (msg instanceof String) return (String) msg;
        try {
            return objectMapper.writeValueAsString(msg);
        } catch (Exception e) {
            return "[Unserializable / Circular Object]";
        }
    }

    /**
     * OTel Java's {@link Attributes} are immutable value objects (unlike
     * JS/Python, where the SpanProcessor can mutate attributes in place in
     * onEnd), so masking has to happen at the exporter boundary instead: a
     * {@link SpanData} wrapper that returns masked attributes, and an
     * exporter decorator that substitutes it in before delegating to the
     * real OTLP exporter. This is what closes the masking gap for
     * auto-instrumented spans (http.url query strings, db.statement
     * literals, etc.), which never went through maskSensitiveData before
     * (only the console bridge did).
     */
    private static final class MaskedSpanData implements SpanData {
        private final SpanData delegate;
        private final Attributes maskedAttributes;

        MaskedSpanData(SpanData delegate) {
            this.delegate = delegate;
            AttributesBuilder builder = delegate.getAttributes().toBuilder();
            delegate.getAttributes().forEach((key, value) -> {
                // Field-name masking only applies to String-typed attributes,
                // matching the scope value-based masking already had - an
                // AttributeKey carries its own value type (Long/Double/
                // Boolean/etc.), and substituting a String value under a
                // non-String-typed key risks a ClassCastException or a
                // silently duplicated attribute entry, depending on the
                // OTel Java Attributes implementation's internal keying. A
                // non-String field named e.g. "credit_score" is left
                // untouched - a documented v1 scope limit, not an oversight.
                if (!(value instanceof String)) return;
                @SuppressWarnings("unchecked")
                AttributeKey<String> stringKey = (AttributeKey<String>) key;
                if (Masking.isSensitiveFieldName(key.getKey())) {
                    builder.put(stringKey, "[FIELD_MASKED]");
                } else {
                    builder.put(stringKey, maskSensitiveData((String) value));
                }
            });
            this.maskedAttributes = builder.build();
        }

        @Override public String getName() { return delegate.getName(); }
        @Override public io.opentelemetry.api.trace.SpanKind getKind() { return delegate.getKind(); }
        @Override public SpanContext getSpanContext() { return delegate.getSpanContext(); }
        @Override public SpanContext getParentSpanContext() { return delegate.getParentSpanContext(); }
        @Override public StatusData getStatus() { return delegate.getStatus(); }
        @Override public long getStartEpochNanos() { return delegate.getStartEpochNanos(); }
        @Override public Attributes getAttributes() { return maskedAttributes; }
        @Override public List<EventData> getEvents() { return delegate.getEvents(); }
        @Override public List<LinkData> getLinks() { return delegate.getLinks(); }
        @Override public long getEndEpochNanos() { return delegate.getEndEpochNanos(); }
        @Override public boolean hasEnded() { return delegate.hasEnded(); }
        @Override public int getTotalRecordedEvents() { return delegate.getTotalRecordedEvents(); }
        @Override public int getTotalRecordedLinks() { return delegate.getTotalRecordedLinks(); }
        @Override public int getTotalAttributeCount() { return delegate.getTotalAttributeCount(); }
        @Override public InstrumentationScopeInfo getInstrumentationScopeInfo() { return delegate.getInstrumentationScopeInfo(); }
        @Override public Resource getResource() { return delegate.getResource(); }
        @Override @SuppressWarnings("deprecation") public InstrumentationLibraryInfo getInstrumentationLibraryInfo() { return delegate.getInstrumentationLibraryInfo(); }
    }

    private static final class MaskingSpanExporter implements SpanExporter {
        private final SpanExporter delegate;

        MaskingSpanExporter(SpanExporter delegate) {
            this.delegate = delegate;
        }

        @Override
        public CompletableResultCode export(Collection<SpanData> spans) {
            List<SpanData> masked = new ArrayList<>(spans.size());
            for (SpanData span : spans) {
                masked.add(new MaskedSpanData(span));
            }
            return delegate.export(masked);
        }

        @Override public CompletableResultCode flush() { return delegate.flush(); }
        @Override public CompletableResultCode shutdown() { return delegate.shutdown(); }
    }

    private static boolean crashCaptureRegistered = false;

    // Keep in sync with pom.xml's <version> on each release - no build-time
    // manifest injection is set up to read this automatically, so unlike
    // owl24-py's importlib.metadata-based lookup, this has to be maintained
    // by hand here.
    private static final String SDK_VERSION = "0.1.3";

    /**
     * Called once at the very start of init() - separate from the OTLP
     * exporters below, since their interfaces only ever expose a
     * {@link CompletableResultCode} (success/failure), never the underlying
     * HTTP response, so there's no way to detect ingestor.js's 426 Upgrade
     * Required from inside a normal export call. A short timeout and a
     * blanket catch mean a slow/unreachable server here degrades to
     * "assume fine, proceed" rather than delaying or breaking the host
     * app's own startup.
     */
    private static boolean checkSdkVersion(String ingestBaseUrl, String apiKey, String userEmail, Duration timeout) {
        try {
            HttpClient client = HttpClient.newBuilder().connectTimeout(timeout).build();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(ingestBaseUrl + "/v1/sdk-check"))
                    .header("x-api-key", apiKey)
                    .header("x-user-email", userEmail)
                    .header("x-sdk-language", "java")
                    .header("x-sdk-version", SDK_VERSION)
                    .timeout(timeout)
                    .POST(HttpRequest.BodyPublishers.noBody())
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            Map<?, ?> body = objectMapper.readValue(response.body(), Map.class);
            if (Boolean.TRUE.equals(body.get("update_required"))) {
                System.err.println("[Owl24] Please Update package. telemetry shutting down");
                return true;
            }
            return false;
        } catch (Exception e) {
            // Unreachable/unexpected response: fail open (assume the
            // version is fine) rather than blocking a customer's app
            // startup on an ingest endpoint being temporarily unavailable.
            return false;
        }
    }

    public static void init(String apiKey, String serviceName) {
        // 10s (was 3s): a deliberate compromise batching window - long
        // enough to meaningfully cut ingest request volume/cost, short
        // enough to not badly degrade alerting/dashboard freshness (30s was
        // considered and rejected as too slow for this product's
        // "solve incidents fast" positioning). Shared by traces/logs AND
        // metrics, since this SDK has a single exportInterval, not a
        // separate metrics-only one (unlike the Python sibling) - an
        // accepted existing coupling, not something this change fixes.
        init(apiKey, serviceName, 10000, false);
    }

    public static void init(String apiKey, String serviceName, long exportIntervalMillis, boolean disableConsoleBridge) {
        init(apiKey, serviceName, exportIntervalMillis, disableConsoleBridge, false, 5000);
    }

    public static void init(String apiKey, String serviceName, long exportIntervalMillis, boolean disableConsoleBridge,
                             boolean disableCrashCapture, long exportTimeoutMillis) {
        init(apiKey, serviceName, exportIntervalMillis, disableConsoleBridge, disableCrashCapture, exportTimeoutMillis, null);
    }

    /**
     * Most general overload: also accepts an ingest base URL override, for
     * self-hosted customers pointing this SDK at their own collector
     * instead of owl24's hosted ingest endpoint. Pass {@code null} (or an
     * empty string) to keep the hosted default - every shorter overload
     * above delegates down to this one that way, so their behavior is
     * unchanged.
     */
    public static void init(String apiKey, String serviceName, long exportIntervalMillis, boolean disableConsoleBridge,
                             boolean disableCrashCapture, long exportTimeoutMillis, String ingestBaseUrlOverride) {
        String resolvedApiKey = (apiKey != null) ? apiKey : System.getenv("owl24_API_KEY");
        if (resolvedApiKey == null) resolvedApiKey = System.getenv("OBSERVE_API_KEY");

        String userEmail = System.getenv("owl24_USER_EMAIL");
        if (userEmail == null) userEmail = System.getenv("OBSERVE_USER_EMAIL");
        if (userEmail == null) userEmail = "unknown@local.dev";

        // Defaults to owl24's hosted ingest endpoint, same as
        // owl24-web's ingestBaseUrl option - overridable via
        // ingestBaseUrlOverride for self-hosted customers running their own
        // collector.
        String ingestBaseUrl = (ingestBaseUrlOverride != null && !ingestBaseUrlOverride.isEmpty())
                ? ingestBaseUrlOverride : "https://ingest.owl24.dev";

        if (resolvedApiKey == null) {
            System.err.println("[Owl24] API Key required.");
            return;
        }

        // Server-side version gate (ingestor.js) refuses actual telemetry
        // ingestion from a version this far behind anyway - checking here
        // first means a customer running a known-bad old release finds out
        // via a clear log line at startup, instead of every export
        // silently failing with no explanation.
        if (checkSdkVersion(ingestBaseUrl, resolvedApiKey, userEmail, Duration.ofMillis(exportTimeoutMillis))) {
            return;
        }

        // Any failure below (bad ingest URL, exporter/provider construction
        // error) must not crash the host application - an observability
        // SDK failing to initialize should degrade to a no-op, not take the
        // customer's app down with it.
        //
        // The core pipeline (resource/exporters/providers/SDK) is one
        // inseparable unit - nothing else in this method is usable without
        // it, so it stays a single try/catch that bails out entirely on
        // failure. Everything after it is independent and best-effort:
        // failures there are collected in initIssues and reported, but must
        // not take down pipelines that already succeeded (previously, one
        // catch (Throwable) wrapped the *entire* method body, so e.g. a
        // runtime-metrics registration failure would silently discard an
        // already-working trace/log pipeline and report one generic
        // "Init failed").
        try {
            Duration exportInterval = Duration.ofMillis(exportIntervalMillis);
            // Explicit per-attempt timeout on every exporter (default OTel
            // Java behavior otherwise has no timeout set on the builder,
            // which falls back to a longer library default) - this is what
            // makes the crash-capture flush below actually bounded instead
            // of an unreachable endpoint being able to stall it. See the
            // equivalent, empirically-verified fix in owl24-py.
            Duration exportTimeout = Duration.ofMillis(exportTimeoutMillis);
            // Using safe, raw string keys to prevent deprecation and missing artifact exceptions
            Resource resource = Resource.getDefault().toBuilder()
                    .put(AttributeKey.stringKey("service.name"), serviceName != null ? serviceName : "dice-server")
                    .put(AttributeKey.stringKey("service.version"), "0.1.0")
                    .build();

            OtlpHttpSpanExporter traceExporter = OtlpHttpSpanExporter.builder()
                    .setEndpoint(ingestBaseUrl + "/v1/traces")
                    .addHeader("x-api-key", resolvedApiKey)
                    .addHeader("x-user-email", userEmail)
                    .addHeader("x-sdk-language", "java")
                    .addHeader("x-sdk-version", SDK_VERSION)
                    .setTimeout(exportTimeout)
                    .setCompression("gzip")
                    .build();

            OtlpHttpMetricExporter metricExporter = OtlpHttpMetricExporter.builder()
                    .setEndpoint(ingestBaseUrl + "/v1/metrics")
                    .addHeader("x-api-key", resolvedApiKey)
                    .addHeader("x-user-email", userEmail)
                    .addHeader("x-sdk-language", "java")
                    .addHeader("x-sdk-version", SDK_VERSION)
                    .setTimeout(exportTimeout)
                    .setCompression("gzip")
                    .build();

            OtlpHttpLogRecordExporter logExporter = OtlpHttpLogRecordExporter.builder()
                    .setEndpoint(ingestBaseUrl + "/v1/logs")
                    .addHeader("x-api-key", resolvedApiKey)
                    .addHeader("x-user-email", userEmail)
                    .addHeader("x-sdk-language", "java")
                    .addHeader("x-sdk-version", SDK_VERSION)
                    .setTimeout(exportTimeout)
                    .setCompression("gzip")
                    .build();

            // Tracks whether each of traces/metrics/logs is actually getting
            // through (not just whether it was built without error) - logs
            // "<signal> working"/"<signal> not working because: ..." on
            // each transition and the "engaged fully/partially/failed to
            // engage" aggregate once all 3 have resolved at least once.
            statusTracker = new Owl24StatusTracker(exportTimeoutMillis);

            SdkLoggerProvider loggerProvider = SdkLoggerProvider.builder()
                    .setResource(resource)
                    .addLogRecordProcessor(BatchLogRecordProcessor.builder(new StatusTrackingExporters.Logs(logExporter, statusTracker))
                            .setScheduleDelay(exportInterval)
                            .setMaxExportBatchSize(2048)
                            .setMaxQueueSize(8192)
                            .build())
                    .build();

            SdkMeterProvider meterProvider = SdkMeterProvider.builder()
                    .setResource(resource)
                    .registerMetricReader(PeriodicMetricReader.builder(new StatusTrackingExporters.Metrics(metricExporter, statusTracker)).setInterval(exportInterval).build())
                    .build();

            SdkTracerProvider tracerProvider = SdkTracerProvider.builder()
                    .setResource(resource)
                    .addSpanProcessor(BatchSpanProcessor.builder(new StatusTrackingExporters.Traces(new MaskingSpanExporter(traceExporter), statusTracker))
                            .setScheduleDelay(exportInterval)
                            .setMaxExportBatchSize(2048)
                            .setMaxQueueSize(8192)
                            .build())
                    .addSpanProcessor(new Owl24DbMetricsSpanProcessor(meterProvider))
                    .build();

            openTelemetrySdk = OpenTelemetrySdk.builder()
                    .setTracerProvider(tracerProvider)
                    .setMeterProvider(meterProvider)
                    .setLoggerProvider(loggerProvider)
                    .buildAndRegisterGlobal();

            otelLogger = openTelemetrySdk.getSdkLoggerProvider().get("console-bridge");
            eventIngestConfig = new EventIngestConfig(ingestBaseUrl, resolvedApiKey, userEmail, serviceName != null ? serviceName : "dice-server");

            // Startup jitter: a one-time, non-blocking forceFlush() at a
            // random point in [0, 10s) after init() has already finished
            // building/registering everything synchronously (spans must
            // still be capturable from t=0 - this must never delay that,
            // since doing so would be a real regression for k8s readiness
            // probes / fast-starting hosts). This only smooths out the
            // very first export's timing across many instances starting at
            // once (e.g. a fleet rollout); it never delays init() itself.
            // delayedExecutor requires Java 9+; this package targets 17
            // (see pom.xml), so it's safe here. Best-effort: any failure is
            // swallowed, never thrown back into the host app.
            try {
                long jitterMillis = java.util.concurrent.ThreadLocalRandom.current().nextLong(10000);
                SdkTracerProvider jitterTracerProvider = tracerProvider;
                SdkLoggerProvider jitterLoggerProvider = loggerProvider;
                java.util.concurrent.CompletableFuture
                        .delayedExecutor(jitterMillis, TimeUnit.MILLISECONDS)
                        .execute(() -> {
                            try {
                                jitterTracerProvider.forceFlush();
                                jitterLoggerProvider.forceFlush();
                            } catch (Throwable flushError) {
                                // Best-effort only - never let a failure here
                                // surface anywhere the host app would notice.
                            }
                        });
            } catch (Throwable e) {
                // Scheduling itself failed (e.g. rejected execution) -
                // degrade to no jitter rather than affect startup.
            }
        } catch (Throwable e) {
            // Throwable, not just Exception: a classpath/dependency problem
            // (e.g. NoClassDefFoundError from a missing transitive exporter
            // dependency) is an Error, not an Exception, and would
            // otherwise still crash the host app despite this try/catch.
            System.err.println("[Owl24] Core init failed: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            return;
        }

        // Bridge setup runs first, before runtime metrics/crash capture, so
        // that every "[Owl24] ... failed" line printed by the steps below
        // is itself forwarded through System.err to the dashboard as an
        // ERROR-severity log event - not just visible locally. These are
        // setup-time issues (did a piece install correctly), a different
        // question from whether the trace/metric/log pipelines are actually
        // getting data through - that's tracked separately by
        // statusTracker and logged as each signal resolves.
        if (!disableConsoleBridge) {
            try {
                setupConsoleBridge();
                setupJulBridge();
            } catch (Throwable e) {
                // Bridge may be half-installed here, so use ORIGINAL_ERR
                // rather than risk this message routing through a
                // partially-overridden System.err.
                ORIGINAL_ERR.println("[Owl24] Console bridge setup failed: " + e.getMessage());
            }

            try {
                Owl24LogbackAppender.tryInstall();
            } catch (LinkageError e) {
                // Expected on the large majority of host apps: Logback
                // simply isn't on the classpath. Not an issue worth
                // reporting, since owl24-java doesn't require it.
            } catch (Throwable e) {
                System.err.println("[Owl24] Logback bridge setup failed: " + e.getMessage());
            }
        }

        // JVM runtime metrics (CPU/memory/GC/threads/classes) - the Java
        // equivalent of owl24-js's HostMetrics. This version of the
        // instrumentation library predates the unified RuntimeMetrics
        // facade, so each observer is registered individually.
        try {
            runtimeMetricsHandles.addAll(Classes.registerObservers(openTelemetrySdk));
            runtimeMetricsHandles.addAll(Cpu.registerObservers(openTelemetrySdk));
            runtimeMetricsHandles.addAll(GarbageCollector.registerObservers(openTelemetrySdk));
            runtimeMetricsHandles.addAll(MemoryPools.registerObservers(openTelemetrySdk));
            runtimeMetricsHandles.addAll(Threads.registerObservers(openTelemetrySdk));
        } catch (Throwable e) {
            System.err.println("[Owl24] Runtime metrics registration failed: " + e.getMessage());
        }

        if (!disableCrashCapture) {
            try {
                setupCrashCapture(exportTimeoutMillis);
            } catch (Throwable e) {
                System.err.println("[Owl24] Crash capture setup failed: " + e.getMessage());
            }
        }

        try {
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                System.out.println("Shutting down telemetry...");
                for (AutoCloseable handle : runtimeMetricsHandles) {
                    try {
                        handle.close();
                    } catch (Exception closeError) {
                        ORIGINAL_ERR.println("[Owl24] Failed to close a runtime metrics observer: " + closeError.getMessage());
                    }
                }
                openTelemetrySdk.close();
            }));
        } catch (Throwable e) {
            System.err.println("[Owl24] Shutdown hook registration failed: " + e.getMessage());
        }
    }

    public static void trackEvent(String name) {
        trackEvent(name, null);
    }

    /**
     * Task H (competitive-roadmap.md) - marks a discrete event (a deploy, a
     * feature-flag flip, a customer-defined business event) so it shows up
     * as a marker on the dashboard's time-series charts. Fire-and-forget via
     * {@code sendAsync} (matching owl24-js's non-awaited fetch) so a slow/
     * unreachable ingest endpoint never blocks the caller's own request
     * path. {@code attributes} values are masked the same way span/log
     * attributes are before they ever leave this process - only String-typed
     * values go through the value-pattern pass (matching MaskingSpanExporter's
     * own restriction, since only strings can be pattern-matched), but every
     * key still goes through the field-NAME check regardless of its value's
     * type.
     */
    public static void trackEvent(String name, Map<String, Object> attributes) {
        EventIngestConfig config = eventIngestConfig;
        if (config == null) {
            System.err.println("[Owl24] trackEvent() called before init().");
            return;
        }
        if (name == null || name.isEmpty()) {
            System.err.println("[Owl24] trackEvent() requires a non-empty name.");
            return;
        }

        Map<String, Object> masked = new java.util.HashMap<>();
        if (attributes != null) {
            for (Map.Entry<String, Object> entry : attributes.entrySet()) {
                Object value = entry.getValue();
                if (Masking.isSensitiveFieldName(entry.getKey())) {
                    masked.put(entry.getKey(), "[FIELD_MASKED]");
                } else if (value instanceof String) {
                    masked.put(entry.getKey(), Masking.maskSensitiveData((String) value));
                } else {
                    masked.put(entry.getKey(), value);
                }
            }
        }

        try {
            Map<String, Object> body = new java.util.HashMap<>();
            body.put("name", name);
            body.put("serviceName", config.serviceName);
            body.put("attributes", masked);
            String json = objectMapper.writeValueAsString(body);

            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(config.ingestBaseUrl + "/v1/events"))
                    .header("x-api-key", config.apiKey)
                    .header("x-user-email", config.userEmail)
                    .header("x-sdk-language", "java")
                    .header("x-sdk-version", SDK_VERSION)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8))
                    .build();
            client.sendAsync(request, HttpResponse.BodyHandlers.discarding())
                    .exceptionally(e -> {
                        System.err.println("[Owl24] trackEvent() failed: " + e.getMessage());
                        return null;
                    });
        } catch (Exception e) {
            System.err.println("[Owl24] trackEvent() failed: " + e.getMessage());
        }
    }

    /**
     * There's no OTel auto-instrumentation for the JDK's built-in
     * {@code com.sun.net.httpserver.HttpServer} (unlike Express/Flask, which
     * have dedicated instrumentation libraries) - a host app using it has to
     * create spans manually. Returns a no-op tracer if called before
     * init(), rather than throwing, consistent with the rest of this SDK
     * degrading to a no-op instead of taking the host app down.
     */
    public static Tracer getTracer() {
        if (openTelemetrySdk == null) {
            return io.opentelemetry.api.trace.TracerProvider.noop().get("owl24-java");
        }
        return openTelemetrySdk.getTracer("owl24-java");
    }

    /**
     * Wraps a JDBC {@link DataSource} so every connection/statement it hands
     * out is traced, tagged with the {@code db.system}/{@code db.name} OTel
     * semantic-convention attributes - the Java equivalent of what
     * getNodeAutoInstrumentations() and owl24-py's psycopg2/pymongo/pymysql/
     * sqlalchemy instrumentors give those SDKs for free. Java has no
     * agent-free way to auto-tag JDBC calls the way those do, so a host app
     * has to opt in explicitly by wrapping its {@code DataSource} bean with
     * this. Spans produced this way are picked up by
     * {@link Owl24DbMetricsSpanProcessor} the same as any other
     * {@code db.system}-tagged span, and reported as
     * {@code db.query.count}/{@code db.query.duration_ms}/
     * {@code db.query.error_count}.
     *
     * <p>Returns the original {@code dataSource} unwrapped if called before
     * {@link #init}, consistent with the rest of this SDK degrading to a
     * no-op instead of taking the host app down.
     */
    public static DataSource instrumentDataSource(DataSource dataSource) {
        if (openTelemetrySdk == null) {
            return dataSource;
        }
        return JdbcTelemetry.create(openTelemetrySdk).wrap(dataSource);
    }

    /**
     * Registers a process-wide default uncaught-exception handler: any
     * thread whose exception isn't caught anywhere (and has no
     * thread-specific handler of its own) lands here. Without this, a
     * fatal error just prints its stack trace via the JVM's built-in
     * default handler and telemetry describing it is never sent - the
     * SDK's own batch processors won't get a chance to flush before the
     * JVM decides to exit (or, for a non-main thread, before the app
     * carries on with no record the crash ever happened).
     *
     * Deliberately treats ANY uncaught exception, on any thread, as fatal
     * enough to shut the whole process down after capturing it - a
     * documented, opt-out-able design choice (disableCrashCapture),
     * consistent with the general principle that once you install a
     * handler for this, continuing to run in a possibly-corrupted state is
     * riskier than exiting.
     */
    private static void setupCrashCapture(long exportTimeoutMillis) {
        if (crashCaptureRegistered) return;
        crashCaptureRegistered = true;

        Thread.setDefaultUncaughtExceptionHandler((thread, throwable) -> {
            try {
                StringBuilder sb = new StringBuilder("[uncaught_exception] on thread \"" + thread.getName() + "\": " + throwable);
                for (StackTraceElement el : throwable.getStackTrace()) {
                    sb.append("\n\tat ").append(el);
                }
                otelLogger.logRecordBuilder()
                        .setBody(maskSensitiveData(sb.toString()))
                        .setSeverity(Severity.FATAL)
                        .setSeverityText("FATAL")
                        .setAttribute(AttributeKey.stringKey("error.type"), "uncaught_exception")
                        .setAttribute(AttributeKey.stringKey("thread.name"), thread.getName())
                        .emit();
            } catch (Throwable loggingError) {
                ORIGINAL_ERR.println("[Owl24] Failed to record crash event: " + loggingError.getMessage());
            }

            ORIGINAL_ERR.println("[Owl24] Uncaught exception on thread \"" + thread.getName() + "\":");
            throwable.printStackTrace(ORIGINAL_ERR);

            try {
                // Bounded by the exporter-level timeout set in init() (x2,
                // one attempt for logs + one for spans/metrics) - shutdown()
                // itself has no timeout parameter, so without a bounded
                // exporter timeout underneath, this could block indefinitely
                // against an unreachable endpoint instead of ever exiting.
                openTelemetrySdk.shutdown().join(exportTimeoutMillis * 2, TimeUnit.MILLISECONDS);
            } catch (Throwable flushError) {
                ORIGINAL_ERR.println("[Owl24] Failed to flush telemetry before exit: " + flushError.getMessage());
            }

            System.exit(1);
        });
    }

    /**
     * Only println(String) was previously overridden. PrintStream.println(Object)
     * does NOT delegate to println(String) internally (it calls String.valueOf
     * then its own print/newline path), so System.out.println(someObject),
     * print(...), and printf(...) all bypassed the bridge entirely with no
     * indication anything was missed. Overriding the String/Object/printf
     * entry points here covers the realistic range of console logging calls.
     */
    private static void setupConsoleBridge() {
        PrintStream originalOut = System.out;
        PrintStream originalErr = System.err;

        System.setOut(new PrintStream(originalOut) {
            @Override
            public void println(String x) {
                originalOut.println(x);
                emitLog(x, "INFO", Severity.INFO);
            }

            @Override
            public void println(Object x) {
                originalOut.println(x);
                emitLog(x, "INFO", Severity.INFO);
            }

            @Override
            public void print(String x) {
                originalOut.print(x);
                emitLog(x, "INFO", Severity.INFO);
            }

            @Override
            public void print(Object x) {
                originalOut.print(x);
                emitLog(x, "INFO", Severity.INFO);
            }

            @Override
            public PrintStream printf(String format, Object... args) {
                originalOut.printf(format, args);
                emitLog(String.format(format, args), "INFO", Severity.INFO);
                return this;
            }
        });

        System.setErr(new PrintStream(originalErr) {
            @Override
            public void println(String x) {
                originalErr.println(x);
                emitLog(x, "ERROR", Severity.ERROR);
            }

            @Override
            public void println(Object x) {
                originalErr.println(x);
                emitLog(x, "ERROR", Severity.ERROR);
            }

            @Override
            public void print(String x) {
                originalErr.print(x);
                emitLog(x, "ERROR", Severity.ERROR);
            }

            @Override
            public void print(Object x) {
                originalErr.print(x);
                emitLog(x, "ERROR", Severity.ERROR);
            }

            @Override
            public PrintStream printf(String format, Object... args) {
                originalErr.printf(format, args);
                emitLog(String.format(format, args), "ERROR", Severity.ERROR);
                return this;
            }
        });
    }

    /**
     * Captures java.util.logging output.
     *
     * Added 2026-09-19 after running clientservers/java-server against a local
     * collector: the System.out/System.err bridge above misses JUL entirely,
     * because java.util.logging's ConsoleHandler grabs a direct reference to
     * System.err when it is constructed - which happens on first logger use,
     * typically at class-load of a class holding a static Logger, i.e. BEFORE
     * Owl24.init() ever runs. Replacing System.err afterwards cannot affect a
     * handler that already captured the original stream.
     *
     * The practical effect was that {@code LOGGER.log(Level.SEVERE, "...", e)}
     * - the ordinary way Java code reports an error - produced nothing at all
     * in the dashboard, while a bare System.out.println was captured fine.
     * Since almost no real Java service logs via System.out, error logs and
     * their stack traces were effectively invisible for Java customers.
     *
     * Attaching a Handler to the root logger sidesteps stream interception
     * completely, and mirrors what owl24-py already does with Python's
     * logging module.
     */
    private static void setupJulBridge() {
        java.util.logging.Logger root = LogManager.getLogManager().getLogger("");
        if (root == null) {
            return;
        }
        // Formatter.formatMessage resolves the record's message and any
        // {0}-style parameters. Handler itself has no such method, and
        // record.getMessage() alone would leave placeholders unsubstituted.
        final SimpleFormatter formatter = new SimpleFormatter();
        root.addHandler(new Handler() {
            @Override
            public void publish(LogRecord record) {
                if (record == null || !isLoggable(record)) {
                    return;
                }
                // Never bridge our own output - emitLog failures log via
                // System.err, which would otherwise loop straight back here.
                String loggerName = record.getLoggerName();
                if (loggerName != null && loggerName.startsWith("dev.owl24")) {
                    return;
                }
                try {
                    StringBuilder body = new StringBuilder();
                    body.append(formatter.formatMessage(record));

                    // The throwable is the whole point: without it an error log
                    // is one line of prose and the stack trace - the single most
                    // useful artifact for root-cause analysis - is discarded.
                    Throwable thrown = record.getThrown();
                    if (thrown != null) {
                        StringWriter sw = new StringWriter();
                        thrown.printStackTrace(new PrintWriter(sw));
                        body.append(System.lineSeparator()).append(sw);
                    }

                    boolean isError = record.getLevel().intValue() >= Level.WARNING.intValue();
                    emitLog(body.toString(),
                            isError ? "ERROR" : "INFO",
                            isError ? Severity.ERROR : Severity.INFO);
                } catch (Throwable ignored) {
                    // A logging bridge must never break the caller's request.
                }
            }

            @Override
            public void flush() { }

            @Override
            public void close() { }
        });
    }

    static void emitLog(Object msg, String level, Severity severity) {
        try {
            String body = safeSerialize(msg);
            String maskedBody = maskSensitiveData(body);

            SpanContext spanContext = Span.current().getSpanContext();
            String traceId = spanContext.isValid() ? spanContext.getTraceId() : null;
            String spanId = spanContext.isValid() ? spanContext.getSpanId() : null;

            otelLogger.logRecordBuilder()
                    .setBody(maskedBody)
                    .setSeverity(severity)
                    .setSeverityText(level)
                    .setAttribute(AttributeKey.stringKey("manual.trace_id"), traceId)
                    .setAttribute(AttributeKey.stringKey("manual.span_id"), spanId)
                    .setAttribute(AttributeKey.stringKey("is_winston"), "false")
                    .emit();
        } catch (Exception e) {
            System.err.println("[Owl24] Bridge error: " + e.getMessage());
        }
    }
}
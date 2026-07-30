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

import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

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
    private static final Map<String, Pattern> MASK_PATTERNS = new HashMap<>();

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
        MASK_PATTERNS.put("email", Pattern.compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"));
        MASK_PATTERNS.put("creditCard", Pattern.compile("\\b(?:\\d[ -]*?){13,16}\\b"));
        MASK_PATTERNS.put("phone", Pattern.compile("(\\+?\\d{1,3}[-.\\s]?)?\\(?\\d{3}\\)?[-.\\s]?\\d{3}[-.\\s]?\\d{4}"));
        MASK_PATTERNS.put("bearerToken", Pattern.compile("Bearer\\s+[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*"));
    }

    static String maskSensitiveData(String text) {
        if (text == null) return null;
        text = MASK_PATTERNS.get("email").matcher(text).replaceAll("[EMAIL_MASKED]");
        text = MASK_PATTERNS.get("creditCard").matcher(text).replaceAll("[CARD_MASKED]");
        text = MASK_PATTERNS.get("phone").matcher(text).replaceAll("[PHONE_MASKED]");
        text = MASK_PATTERNS.get("bearerToken").matcher(text).replaceAll("[TOKEN_MASKED]");
        return text;
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
                if (value instanceof String) {
                    @SuppressWarnings("unchecked")
                    AttributeKey<String> stringKey = (AttributeKey<String>) key;
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

    public static void init(String apiKey, String serviceName) {
        init(apiKey, serviceName, 3000, false);
    }

    public static void init(String apiKey, String serviceName, long exportIntervalMillis, boolean disableConsoleBridge) {
        init(apiKey, serviceName, exportIntervalMillis, disableConsoleBridge, false, 5000);
    }

    public static void init(String apiKey, String serviceName, long exportIntervalMillis, boolean disableConsoleBridge,
                             boolean disableCrashCapture, long exportTimeoutMillis) {
        String resolvedApiKey = (apiKey != null) ? apiKey : System.getenv("owl24_API_KEY");
        if (resolvedApiKey == null) resolvedApiKey = System.getenv("OBSERVE_API_KEY");

        String userEmail = System.getenv("owl24_USER_EMAIL");
        if (userEmail == null) userEmail = System.getenv("OBSERVE_USER_EMAIL");
        if (userEmail == null) userEmail = "unknown@local.dev";

        // Hardcoded, not configurable: owl24 is a fully-hosted service with
        // one fixed ingest endpoint - unlike the API key (per-customer) or
        // user email, there's nothing for a caller to legitimately point
        // this at instead.
        String ingestBaseUrl = "https://ingest.owl24.dev";

        if (resolvedApiKey == null) {
            System.err.println("[Owl24] API Key required.");
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
                    .setTimeout(exportTimeout)
                    .build();

            OtlpHttpMetricExporter metricExporter = OtlpHttpMetricExporter.builder()
                    .setEndpoint(ingestBaseUrl + "/v1/metrics")
                    .addHeader("x-api-key", resolvedApiKey)
                    .addHeader("x-user-email", userEmail)
                    .setTimeout(exportTimeout)
                    .build();

            OtlpHttpLogRecordExporter logExporter = OtlpHttpLogRecordExporter.builder()
                    .setEndpoint(ingestBaseUrl + "/v1/logs")
                    .addHeader("x-api-key", resolvedApiKey)
                    .addHeader("x-user-email", userEmail)
                    .setTimeout(exportTimeout)
                    .build();

            // Tracks whether each of traces/metrics/logs is actually getting
            // through (not just whether it was built without error) - logs
            // "<signal> working"/"<signal> not working because: ..." on
            // each transition and the "engaged fully/partially/failed to
            // engage" aggregate once all 3 have resolved at least once.
            statusTracker = new Owl24StatusTracker(exportTimeoutMillis);

            SdkLoggerProvider loggerProvider = SdkLoggerProvider.builder()
                    .setResource(resource)
                    .addLogRecordProcessor(BatchLogRecordProcessor.builder(new StatusTrackingExporters.Logs(logExporter, statusTracker)).setScheduleDelay(exportInterval).build())
                    .build();

            SdkMeterProvider meterProvider = SdkMeterProvider.builder()
                    .setResource(resource)
                    .registerMetricReader(PeriodicMetricReader.builder(new StatusTrackingExporters.Metrics(metricExporter, statusTracker)).setInterval(exportInterval).build())
                    .build();

            SdkTracerProvider tracerProvider = SdkTracerProvider.builder()
                    .setResource(resource)
                    .addSpanProcessor(BatchSpanProcessor.builder(new StatusTrackingExporters.Traces(new MaskingSpanExporter(traceExporter), statusTracker)).setScheduleDelay(exportInterval).build())
                    .build();

            openTelemetrySdk = OpenTelemetrySdk.builder()
                    .setTracerProvider(tracerProvider)
                    .setMeterProvider(meterProvider)
                    .setLoggerProvider(loggerProvider)
                    .buildAndRegisterGlobal();

            otelLogger = openTelemetrySdk.getSdkLoggerProvider().get("console-bridge");
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
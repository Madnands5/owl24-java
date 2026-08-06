package dev.owl24.apm;

import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.common.AttributesBuilder;
import io.opentelemetry.api.metrics.DoubleHistogram;
import io.opentelemetry.api.metrics.LongCounter;
import io.opentelemetry.api.metrics.Meter;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.context.Context;
import io.opentelemetry.sdk.common.CompletableResultCode;
import io.opentelemetry.sdk.metrics.SdkMeterProvider;
import io.opentelemetry.sdk.trace.ReadWriteSpan;
import io.opentelemetry.sdk.trace.ReadableSpan;
import io.opentelemetry.sdk.trace.SpanProcessor;

/**
 * Derives DB query metrics (count, duration, errors) from spans tagged with
 * the {@code db.system} OTel semantic-convention attribute - the Java
 * equivalent of owl24-js's {@code DbMetricsSpanProcessor}. A span gets that
 * attribute either from {@link Owl24#instrumentDataSource}'s JDBC wrapping,
 * or from any other library instrumentation the host app installs itself;
 * either way, this processor picks it up the same way.
 *
 * <p>Unlike owl24-js/owl24-py (which look up the global meter provider
 * lazily, since it isn't registered until later in their init sequence),
 * this is constructed with the already-built {@link SdkMeterProvider}
 * directly - by the time {@code Owl24.init()} builds the tracer provider
 * this processor attaches to, the meter provider already exists as a local
 * variable, so there's no ordering problem to work around.
 */
final class Owl24DbMetricsSpanProcessor implements SpanProcessor {

    private static final AttributeKey<String> DB_SYSTEM = AttributeKey.stringKey("db.system");
    private static final AttributeKey<String> DB_NAME = AttributeKey.stringKey("db.name");

    private final LongCounter queryCount;
    private final DoubleHistogram queryDuration;
    private final LongCounter queryErrors;

    Owl24DbMetricsSpanProcessor(SdkMeterProvider meterProvider) {
        Meter meter = meterProvider.get("owl24-db-metrics");
        this.queryCount = meter.counterBuilder("db.query.count")
                .setDescription("Number of database queries observed via auto-instrumented spans")
                .build();
        this.queryDuration = meter.histogramBuilder("db.query.duration_ms")
                .setDescription("Database query duration in milliseconds")
                .setUnit("ms")
                .build();
        this.queryErrors = meter.counterBuilder("db.query.error_count")
                .setDescription("Number of database queries that ended in an error")
                .build();
    }

    @Override
    public void onStart(Context parentContext, ReadWriteSpan span) {
    }

    @Override
    public boolean isStartRequired() {
        return false;
    }

    @Override
    public void onEnd(ReadableSpan span) {
        String dbSystem = span.getAttribute(DB_SYSTEM);
        if (dbSystem == null) {
            return;
        }

        AttributesBuilder attributesBuilder = Attributes.builder().put(DB_SYSTEM, dbSystem);
        String dbName = span.getAttribute(DB_NAME);
        if (dbName != null) {
            attributesBuilder.put(DB_NAME, dbName);
        }
        Attributes attributes = attributesBuilder.build();

        double durationMs = span.getLatencyNanos() / 1_000_000.0;
        queryCount.add(1, attributes);
        queryDuration.record(durationMs, attributes);
        if (span.toSpanData().getStatus().getStatusCode() == StatusCode.ERROR) {
            queryErrors.add(1, attributes);
        }
    }

    @Override
    public boolean isEndRequired() {
        return true;
    }

    @Override
    public CompletableResultCode shutdown() {
        return CompletableResultCode.ofSuccess();
    }

    @Override
    public CompletableResultCode forceFlush() {
        return CompletableResultCode.ofSuccess();
    }
}

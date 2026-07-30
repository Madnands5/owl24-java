package dev.owl24.apm;

import io.opentelemetry.sdk.common.CompletableResultCode;
import io.opentelemetry.sdk.logs.data.LogRecordData;
import io.opentelemetry.sdk.logs.export.LogRecordExporter;
import io.opentelemetry.sdk.metrics.InstrumentType;
import io.opentelemetry.sdk.metrics.data.AggregationTemporality;
import io.opentelemetry.sdk.metrics.data.MetricData;
import io.opentelemetry.sdk.metrics.export.MetricExporter;
import io.opentelemetry.sdk.trace.data.SpanData;
import io.opentelemetry.sdk.trace.export.SpanExporter;

import java.util.Collection;

/**
 * Three thin wrappers, one per signal, each delegating every call straight
 * through to the real exporter except export() itself, which routes through
 * {@link Owl24StatusTracker#track}. Separate classes because SpanExporter,
 * MetricExporter, and LogRecordExporter are unrelated OTel interfaces with
 * no common supertype - the actual retry/state-machine logic lives once in
 * Owl24StatusTracker; these just adapt it to each interface's shape.
 */
final class StatusTrackingExporters {
    private StatusTrackingExporters() {}

    static final class Traces implements SpanExporter {
        private final SpanExporter delegate;
        private final Owl24StatusTracker tracker;

        Traces(SpanExporter delegate, Owl24StatusTracker tracker) {
            this.delegate = delegate;
            this.tracker = tracker;
        }

        @Override
        public CompletableResultCode export(Collection<SpanData> spans) {
            return tracker.track("traces", () -> delegate.export(spans));
        }

        @Override public CompletableResultCode flush() { return delegate.flush(); }
        @Override public CompletableResultCode shutdown() { return delegate.shutdown(); }
    }

    static final class Metrics implements MetricExporter {
        private final MetricExporter delegate;
        private final Owl24StatusTracker tracker;

        Metrics(MetricExporter delegate, Owl24StatusTracker tracker) {
            this.delegate = delegate;
            this.tracker = tracker;
        }

        @Override
        public CompletableResultCode export(Collection<MetricData> metrics) {
            return tracker.track("metrics", () -> delegate.export(metrics));
        }

        @Override public AggregationTemporality getAggregationTemporality(InstrumentType instrumentType) {
            return delegate.getAggregationTemporality(instrumentType);
        }

        @Override public CompletableResultCode flush() { return delegate.flush(); }
        @Override public CompletableResultCode shutdown() { return delegate.shutdown(); }
    }

    static final class Logs implements LogRecordExporter {
        private final LogRecordExporter delegate;
        private final Owl24StatusTracker tracker;

        Logs(LogRecordExporter delegate, Owl24StatusTracker tracker) {
            this.delegate = delegate;
            this.tracker = tracker;
        }

        @Override
        public CompletableResultCode export(Collection<LogRecordData> logs) {
            return tracker.track("logs", () -> delegate.export(logs));
        }

        @Override public CompletableResultCode flush() { return delegate.flush(); }
        @Override public CompletableResultCode shutdown() { return delegate.shutdown(); }
    }
}

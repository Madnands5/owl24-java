package dev.owl24.apm;

import io.opentelemetry.sdk.common.CompletableResultCode;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * Tracks working/not-working status per signal ("traces"/"metrics"/"logs")
 * and confirms state transitions with a bounded retry before declaring a
 * pipeline down, instead of reacting to a single failed flush - collector
 * hiccups are common and shouldn't cause a false "not working" the moment a
 * scheduled export overlaps a blip.
 *
 * Retries only fire at the two points that matter: the very first export
 * attempt for a signal ("initiating"), and the first failure after a signal
 * was previously confirmed working ("stopped working midway") - NOT on
 * every routine flush while a signal is in a known-good or known-bad
 * steady state. The underlying OTLP exporters already retry/bound
 * themselves internally up to their own configured timeout; wrapping every
 * flush in another round of retries could make one flush take far longer
 * than the scheduled export interval and pile up during an outage.
 */
final class Owl24StatusTracker {

    private enum State { PENDING, WORKING, NOT_WORKING }

    private static final int MAX_ATTEMPTS = 3;
    private static final long[] BACKOFF_MILLIS = { 300, 800 };

    private final Map<String, State> states = new ConcurrentHashMap<>();
    private String lastAggregate;

    private final long joinTimeoutMillis;

    Owl24StatusTracker(long joinTimeoutMillis) {
        // A small margin over the exporter's own configured timeout, so our
        // join() never times out just ahead of the exporter's own internal
        // deadline and misreports a still-in-flight call as an instant failure.
        this.joinTimeoutMillis = joinTimeoutMillis + 1000;
        states.put("traces", State.PENDING);
        states.put("metrics", State.PENDING);
        states.put("logs", State.PENDING);
    }

    /**
     * Wraps one export attempt for {@code signal} with the
     * transition-confirming retry described above. {@code attempt} must be
     * safe to call more than once with the same underlying data - it always
     * is here, since a retry re-sends the same batch, not a fresh fetch.
     */
    CompletableResultCode track(String signal, Supplier<CompletableResultCode> attempt) {
        State current = states.get(signal);

        if (current == State.NOT_WORKING) {
            // Known-down steady state: single attempt, no retry, no repeat
            // log - avoids spamming during a known outage.
            CompletableResultCode result = attempt.get();
            if (result.join(joinTimeoutMillis, TimeUnit.MILLISECONDS).isSuccess()) {
                transitionTo(signal, State.WORKING, null);
            }
            return result;
        }

        // PENDING (initiating) or WORKING (confirming a possible "stopped
        // working midway"): retry the same payload up to MAX_ATTEMPTS total
        // before declaring the signal not-working.
        CompletableResultCode lastResult = null;
        String lastReason = null;
        for (int attemptNum = 1; attemptNum <= MAX_ATTEMPTS; attemptNum++) {
            lastResult = attempt.get();
            CompletableResultCode joined = lastResult.join(joinTimeoutMillis, TimeUnit.MILLISECONDS);
            if (joined.isSuccess()) {
                transitionTo(signal, State.WORKING, null);
                return lastResult;
            }
            Throwable cause = joined.getFailureThrowable();
            lastReason = (cause != null)
                    ? cause.getClass().getSimpleName() + ": " + cause.getMessage()
                    : "export failed (no additional detail available from the exporter)";
            if (attemptNum < MAX_ATTEMPTS) {
                sleepQuietly(BACKOFF_MILLIS[attemptNum - 1]);
            }
        }

        transitionTo(signal, State.NOT_WORKING, lastReason);
        return lastResult;
    }

    private synchronized void transitionTo(String signal, State newState, String reason) {
        State previous = states.put(signal, newState);
        if (previous == newState) {
            return;
        }

        if (newState == State.WORKING) {
            System.out.println("[Owl24] " + signal + " working");
        } else if (newState == State.NOT_WORKING) {
            System.err.println("[Owl24] " + signal + " not working because: " + reason);
        }

        reevaluateAggregate();
    }

    private void reevaluateAggregate() {
        for (State s : states.values()) {
            if (s == State.PENDING) {
                return; // wait until all 3 signals have resolved at least once
            }
        }

        long workingCount = states.values().stream().filter(s -> s == State.WORKING).count();
        String aggregate;
        if (workingCount == states.size()) {
            aggregate = "[Owl24] engaged fully";
        } else if (workingCount == 0) {
            aggregate = "[Owl24] failed to engage";
        } else {
            aggregate = "[Owl24] partially engaged";
        }

        if (!aggregate.equals(lastAggregate)) {
            lastAggregate = aggregate;
            System.out.println(aggregate);
        }
    }

    private static void sleepQuietly(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}

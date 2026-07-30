# owl24-java

Java SDK for [owl24](https://owl24.dev) — one line of code to send logs, traces, and metrics to your owl24 dashboard, built on OpenTelemetry.

## Install

Maven:

```xml
<dependency>
    <groupId>dev.owl24.apm</groupId>
    <artifactId>owl24-java</artifactId>
    <version>0.1.2</version>
</dependency>
```

## Usage

```java
import dev.owl24.apm.Owl24;

public class Main {
    public static void main(String[] args) {
        Owl24.init(System.getenv("OWL24_API_KEY"), "my-service-name");
    }
}
```

That's it — `Owl24.init(...)` wires up an OpenTelemetry tracer/meter/logger provider pointed at your owl24 ingest endpoint, registers JVM runtime metrics (CPU/memory/GC/threads/classes), bridges `System.out`/`System.err` so console output is automatically sent to your dashboard alongside the current trace/span ID, and — if Logback is on the classpath (true for a default Spring Boot app) — bridges SLF4J/Logback logging too, so your normal `logger.info(...)` calls are captured without any extra setup.

Each of these pieces is independent: if one fails to set up (say, JVM runtime metrics can't register on an unusual JVM), the others keep working — you'll see a `[Owl24] ... failed` line naming exactly which piece it was, instead of the whole SDK going quiet.

### Options

```java
Owl24.init(
    apiKey,              // or set OWL24_API_KEY / OBSERVE_API_KEY env var
    "my-service-name",
    3000,                // exportIntervalMillis
    false,               // disableConsoleBridge
    false,               // disableCrashCapture
    5000                 // exportTimeoutMillis
);
```

Telemetry is always sent to `https://ingest.owl24.dev` — owl24's ingest endpoint isn't configurable, since it's a fixed part of the hosted service (only the API key is per-customer).

### Spring Boot: automatic request tracing

If your app is a Spring Boot app, `Owl24.init(...)` is all you need — no config class, no extra dependency. The SDK ships a Spring Boot auto-configuration that bridges Micrometer's Tracer/Observation API to its own OpenTelemetry SDK, so every servlet request gets a real span with zero manual span code, the same way `WebMvcObservationAutoConfiguration` would for any other tracer.

One knob worth knowing about: Spring Boot samples only 10% of requests by default (`management.tracing.sampling.probability=0.10`). Set it to `1.0` in `application.properties` if you want every request traced (e.g. while testing).

### Manual spans

There's no OpenTelemetry auto-instrumentation for every HTTP framework (e.g. the JDK's built-in `com.sun.net.httpserver.HttpServer`), so for those you create spans manually via `Owl24.getTracer()`:

```java
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.context.Scope;

Tracer tracer = Owl24.getTracer();
Span span = tracer.spanBuilder("handle-request").startSpan();
try (Scope scope = span.makeCurrent()) {
    // ... your code ...
} finally {
    span.end();
}
```

`getTracer()` returns a no-op tracer if called before `Owl24.init()`, so it's always safe to call.

## What it does

- **Logs**: bridges `System.out`/`System.err` — every call is forwarded as a structured log, tagged with the active trace/span ID if one exists. If Logback is present, it also attaches an appender to the root logger so ordinary SLF4J/Logback calls (`logger.info(...)`, `logger.error(...)`, including the attached stack trace) are forwarded the same way — this is what makes Spring Boot's default logging show up without any extra configuration. Both bridges are controlled by the single `disableConsoleBridge` flag.
- **Traces**: sets up an OpenTelemetry `SdkTracerProvider` exporting via OTLP/HTTP. Spans you create manually are masked and exported.
- **JVM runtime metrics**: CPU, memory, GC, thread, and class-loading metrics are collected and exported automatically — no setup required.
- **Crash capture**: installs a default uncaught-exception handler so fatal errors (on any thread) are captured as a FATAL-severity log event and flushed before the process exits.
- **PII masking**: emails, credit-card-shaped numbers, phone numbers, and bearer tokens are scrubbed from span attributes and log bodies before they ever leave your process.

### Logging

All log lines are plain text, no icons: `[Owl24] ...`.

**Setup logging** — `init()` sets up several independent pieces (bridges, runtime metrics, crash capture); if one fails, you'll see `[Owl24] <piece> failed: <reason>` naming exactly which one, without the others being affected. If the core pipeline itself can't be built at all (bad exporter/provider construction), you'll see `[Owl24] Core init failed: <reason>` and `init()` returns — the SDK is a no-op for the rest of the process.

**Pipeline status logging** — separately from setup, each of the three signals reports whether it's actually getting data through, for the life of the process:

- `[Owl24] traces working` / `[Owl24] metrics working` / `[Owl24] logs working` — printed the first time a signal is confirmed delivering (and again after recovering from an outage).
- `[Owl24] traces not working because: <reason>` (same for metrics/logs) — printed once a signal fails 3 consecutive attempts. This only triggers at two points: the very first export attempt for a signal, or the first failure after a signal was previously working — not on every routine flush, so a signal that's already known to be down doesn't spam this line on every scheduled export.
- `[Owl24] engaged fully` / `[Owl24] partially engaged` / `[Owl24] failed to engage` — an aggregate line, re-printed only when it changes, once all three signals have resolved at least once.

This status tracking is entirely local — nothing is reported back to owl24's backend, it's just clearer logging in your own process/console.

## License

MIT — see [LICENSE](https://github.com/Madnands5/owl24/blob/main/packages/owl24-java/LICENSE).

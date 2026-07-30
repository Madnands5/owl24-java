package dev.owl24.apm;

import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.OpenTelemetry;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

/**
 * Picked up automatically via META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports
 * on any Spring Boot host app - no manual bean or config class required.
 *
 * Owl24.init() registers its SDK via buildAndRegisterGlobal(), so exposing
 * GlobalOpenTelemetry.get() here makes Spring Boot's own tracing
 * autoconfiguration (spring-boot-starter-actuator +
 * micrometer-tracing-bridge-otel, both on the classpath unconditionally -
 * see owl24-java's pom.xml) back off creating a second, competing SDK and
 * instead bridge Micrometer's Tracer/Observation API to this one. From
 * there, WebMvcObservationAutoConfiguration wraps every servlet request in
 * a span that reaches Owl24's own masking OTLP exporter - confirmed via the
 * identical manual wiring in clientservers/java-springboot-server's
 * TracingConfig before it was folded into the SDK itself.
 *
 * Guarded by {@code @ConditionalOnMissingBean(OpenTelemetry.class)} so a
 * host app that already defines its own OpenTelemetry bean (e.g. running a
 * second, unrelated tracing setup) isn't overridden by this one.
 */
@AutoConfiguration
public class Owl24SpringAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(OpenTelemetry.class)
    public OpenTelemetry openTelemetry() {
        return GlobalOpenTelemetry.get();
    }
}

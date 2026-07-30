package dev.owl24.apm;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.IThrowableProxy;
import ch.qos.logback.classic.spi.LoggerContextListener;
import ch.qos.logback.classic.spi.ThrowableProxyUtil;
import ch.qos.logback.core.AppenderBase;
import io.opentelemetry.api.logs.Severity;
import org.slf4j.LoggerFactory;

/**
 * Bridges SLF4J/Logback log events (e.g. all default Spring Boot logging,
 * via {@code logger.info(...)}) into the owl24 logger. Logback writes
 * straight to its own cached output stream and never calls
 * System.out/err's print methods, so it's invisible to Owl24's
 * setupConsoleBridge() - this is the missing piece for that case. Every
 * Logback/SLF4J type reference lives only in this file, never in Owl24.java,
 * so that class can call {@link #tryInstall()} inside a
 * {@code catch (Throwable)} and safely no-op (NoClassDefFoundError) when
 * Logback isn't on the host app's classpath at all.
 */
final class Owl24LogbackAppender extends AppenderBase<ILoggingEvent> {

    // Prevents a feedback loop: the OTLP exporter's own HTTP client and the
    // OTel SDK internals log through SLF4J like anything else in the host
    // app - without this, exporting a span/log/metric would itself emit a
    // log event that gets exported, which emits another, forever. Mirrors
    // owl24-py's _EXCLUDED_LOGGER_PREFIXES (telemetry.py).
    private static final String[] EXCLUDED_LOGGER_PREFIXES = {
            "io.opentelemetry",
            "io.grpc",
            "okhttp3",
            "dev.owl24",
    };

    /**
     * Attaches an instance of this appender to the Logback root logger, so
     * every log event handled anywhere in the host app is forwarded to
     * owl24 the same way raw console output already is. Also registers a
     * reset-resistant {@link LoggerContextListener} that re-attaches on
     * every future {@code LoggerContext.reset()} - Spring Boot resets and
     * reconfigures its Logback context during its own logging startup, which
     * would otherwise silently wipe an appender attached before that point
     * (a real risk since this SDK's documented usage is to call init() at
     * the very top of main(), which commonly runs before Spring Boot's
     * logging system has initialized).
     */
    static void tryInstall() {
        LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();
        attachTo(context);
        context.addListener(new ResetResistantReattacher());
    }

    private static void attachTo(LoggerContext context) {
        Owl24LogbackAppender appender = new Owl24LogbackAppender();
        appender.setContext(context);
        appender.start();
        context.getLogger(ch.qos.logback.classic.Logger.ROOT_LOGGER_NAME).addAppender(appender);
    }

    @Override
    protected void append(ILoggingEvent event) {
        String loggerName = event.getLoggerName();
        for (String prefix : EXCLUDED_LOGGER_PREFIXES) {
            if (loggerName.startsWith(prefix)) {
                return;
            }
        }

        StringBuilder body = new StringBuilder(event.getFormattedMessage());
        IThrowableProxy throwableProxy = event.getThrowableProxy();
        if (throwableProxy != null) {
            body.append('\n').append(ThrowableProxyUtil.asString(throwableProxy));
        }

        Owl24.emitLog(body.toString(), event.getLevel().toString(), toOtelSeverity(event.getLevel()));
    }

    private static Severity toOtelSeverity(Level level) {
        switch (level.toInt()) {
            case Level.ERROR_INT: return Severity.ERROR;
            case Level.WARN_INT: return Severity.WARN;
            case Level.INFO_INT: return Severity.INFO;
            case Level.DEBUG_INT: return Severity.DEBUG;
            case Level.TRACE_INT: return Severity.TRACE;
            default: return Severity.INFO;
        }
    }

    private static final class ResetResistantReattacher implements LoggerContextListener {
        @Override public boolean isResetResistant() { return true; }
        @Override public void onStart(LoggerContext context) { }
        @Override public void onReset(LoggerContext context) { attachTo(context); }
        @Override public void onStop(LoggerContext context) { }
        @Override public void onLevelChange(ch.qos.logback.classic.Logger logger, Level level) { }
    }
}

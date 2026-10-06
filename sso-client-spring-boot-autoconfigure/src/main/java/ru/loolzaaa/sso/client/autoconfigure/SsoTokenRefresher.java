package ru.loolzaaa.sso.client.autoconfigure;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.DisposableBean;
import ru.loolzaaa.sso.client.core.security.token.TokenDataReceiver;

import java.time.Duration;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

class SsoTokenRefresher implements DisposableBean {

    private static final Logger log = LogManager.getLogger(SsoTokenRefresher.class.getName());

    private static final Duration DEFAULT_BEFORE_EXPIRY = Duration.ofMinutes(1);
    private static final Duration DEFAULT_CHECK_INTERVAL = Duration.ofSeconds(30);
    private static final long MIN_CHECK_INTERVAL_MILLIS = 1000L;

    private final TokenDataReceiver tokenDataReceiver;
    private final Duration beforeExpiry;

    private ScheduledExecutorService scheduler;

    SsoTokenRefresher(TokenDataReceiver tokenDataReceiver, SsoClientProperties.Refresh refresh) {
        this.tokenDataReceiver = tokenDataReceiver;
        this.beforeExpiry = refresh.getBeforeExpiry() != null ? refresh.getBeforeExpiry() : DEFAULT_BEFORE_EXPIRY;
        if (!refresh.isEnabled()) {
            return;
        }
        Duration checkInterval = refresh.getCheckInterval() != null ? refresh.getCheckInterval() : DEFAULT_CHECK_INTERVAL;
        long intervalMillis = Math.max(checkInterval.toMillis(), MIN_CHECK_INTERVAL_MILLIS);
        this.scheduler = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "sso-token-refresher");
            thread.setDaemon(true);
            return thread;
        });
        this.scheduler.scheduleWithFixedDelay(this::refresh, intervalMillis, intervalMillis, TimeUnit.MILLISECONDS);
    }

    void refresh() {
        try {
            tokenDataReceiver.updateDataIfExpiringWithin(beforeExpiry);
        } catch (Exception e) {
            log.warn("SSO token proactive refresh failed: ", e);
        }
    }

    @Override
    public void destroy() {
        if (scheduler != null) {
            scheduler.shutdownNow();
        }
    }
}

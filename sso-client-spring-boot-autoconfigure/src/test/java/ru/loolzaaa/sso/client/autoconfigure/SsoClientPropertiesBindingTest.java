package ru.loolzaaa.sso.client.autoconfigure;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class SsoClientPropertiesBindingTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(TestConfig.class);

    @Test
    void shouldBindReceiverProperties() {
        contextRunner
                .withPropertyValues(
                        "sso.client.receiver.username=user",
                        "sso.client.receiver.password=pass",
                        "sso.client.receiver.fingerprint=fp",
                        "sso.client.receiver.connect-timeout=1s",
                        "sso.client.receiver.request-timeout=2s",
                        "sso.client.receiver.init-on-startup=false",
                        "sso.client.receiver.refresh.enabled=false",
                        "sso.client.receiver.refresh.before-expiry=5m",
                        "sso.client.receiver.refresh.check-interval=10s")
                .run(context -> {
                    SsoClientProperties properties = context.getBean(SsoClientProperties.class);
                    SsoClientProperties.Receiver receiver = properties.getReceiver();
                    assertThat(receiver.getUsername()).isEqualTo("user");
                    assertThat(receiver.getPassword()).isEqualTo("pass");
                    assertThat(receiver.getFingerprint()).isEqualTo("fp");
                    assertThat(receiver.getConnectTimeout()).isEqualTo(Duration.ofSeconds(1));
                    assertThat(receiver.getRequestTimeout()).isEqualTo(Duration.ofSeconds(2));
                    assertThat(receiver.isInitOnStartup()).isFalse();
                    assertThat(receiver.getRefresh().isEnabled()).isFalse();
                    assertThat(receiver.getRefresh().getBeforeExpiry()).isEqualTo(Duration.ofMinutes(5));
                    assertThat(receiver.getRefresh().getCheckInterval()).isEqualTo(Duration.ofSeconds(10));
                });
    }

    @Test
    void shouldUseDefaults() {
        contextRunner.run(context -> {
            SsoClientProperties properties = context.getBean(SsoClientProperties.class);
            SsoClientProperties.Receiver receiver = properties.getReceiver();
            assertThat(receiver.getConnectTimeout()).isEqualTo(Duration.ofSeconds(4));
            assertThat(receiver.getRequestTimeout()).isEqualTo(Duration.ofSeconds(4));
            assertThat(receiver.isInitOnStartup()).isTrue();
            assertThat(receiver.getRefresh().isEnabled()).isTrue();
            assertThat(receiver.getRefresh().getBeforeExpiry()).isEqualTo(Duration.ofMinutes(1));
            assertThat(receiver.getRefresh().getCheckInterval()).isEqualTo(Duration.ofSeconds(30));
        });
    }

    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties(SsoClientProperties.class)
    static class TestConfig {
    }
}

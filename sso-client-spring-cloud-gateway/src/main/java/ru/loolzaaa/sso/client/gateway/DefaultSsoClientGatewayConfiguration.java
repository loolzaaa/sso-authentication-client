package ru.loolzaaa.sso.client.gateway;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConditionalOnProperty(prefix = "sso.client", value = { "applicationName", "entryPointAddress", "entryPointUri" })
public class DefaultSsoClientGatewayConfiguration {
    @Bean
    @ConditionalOnProperty(prefix = "sso.client.noop-mode", name = "enabled", havingValue = "false")
    JwtGatewayFilter gatewayFilter() {
        return new JwtGatewayFilter();
    }

    @Bean
    @ConditionalOnProperty(prefix = "sso.client.noop-mode", name = "enabled", havingValue = "true")
    NoopGatewayFilter noopGatewayFilter() {
        return new NoopGatewayFilter();
    }
}

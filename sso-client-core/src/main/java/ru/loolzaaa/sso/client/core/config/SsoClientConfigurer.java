package ru.loolzaaa.sso.client.core.config;

import ru.loolzaaa.sso.client.core.security.matcher.BasicAuthenticationConfigurer;
import ru.loolzaaa.sso.client.core.security.matcher.PermitAllMatcherRegistry;
import ru.loolzaaa.sso.client.core.security.matcher.WebhookHandlerRegistry;

public interface SsoClientConfigurer {
    default void addPermitAllMatcher(PermitAllMatcherRegistry registry) {
    }
    default void configureBasicAuthentication(BasicAuthenticationConfigurer configurer) {
    }
    default void addWebhooks(WebhookHandlerRegistry registry) {
    }
}

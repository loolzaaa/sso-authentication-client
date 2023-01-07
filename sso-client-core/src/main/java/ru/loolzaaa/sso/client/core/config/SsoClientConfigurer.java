package ru.loolzaaa.sso.client.core.config;

import ru.loolzaaa.sso.client.core.security.basic.BasicAuthenticationConfigurer;
import ru.loolzaaa.sso.client.core.security.permitall.PermitAllMatcherRegistry;
import ru.loolzaaa.sso.client.core.webhook.WebhookHandlerRegistry;

public interface SsoClientConfigurer {
    default void addPermitAllMatcher(PermitAllMatcherRegistry registry) {
    }
    default void configureBasicAuthentication(BasicAuthenticationConfigurer configurer) {
    }
    default void addWebhooks(WebhookHandlerRegistry registry) {
    }
}

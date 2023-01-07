package ru.loolzaaa.sso.client.autoconfigure;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.util.CollectionUtils;
import ru.loolzaaa.sso.client.core.application.SsoClientWebhookHandler;
import ru.loolzaaa.sso.client.core.config.SsoClientConfigurer;
import ru.loolzaaa.sso.client.core.security.basic.BasicAuthenticationConfigurer;
import ru.loolzaaa.sso.client.core.security.basic.BasicAuthenticationRegistry;
import ru.loolzaaa.sso.client.core.security.permitall.PermitAllMatcher;
import ru.loolzaaa.sso.client.core.security.permitall.PermitAllMatcherRegistry;
import ru.loolzaaa.sso.client.core.webhook.WebhookHandlerRegistry;

import java.util.List;

@Configuration(proxyBeanMethods =  false)
@Import({ SsoClientBasicConfiguration.class, SsoClientJwtConfiguration.class })
public class SsoClientConfiguration {

    private static final Logger log = LogManager.getLogger(SsoClientConfiguration.class.getName());

    private final BasicAuthenticationProperties basicAuthenticationProperties;

    private final SsoClientConfigurer ssoClientConfigurer;

    public SsoClientConfiguration(BasicAuthenticationProperties basicAuthenticationProperties,
                                  @Autowired(required = false) SsoClientConfigurer ssoClientConfigurer) {
        this.basicAuthenticationProperties = basicAuthenticationProperties;
        this.ssoClientConfigurer = ssoClientConfigurer;
    }

    @Bean
    @ConditionalOnMissingBean
    PermitAllMatcherRegistry permitAllMatcherRegistry(List<PermitAllMatcher> permitAllMatchers) {
        PermitAllMatcherRegistry registry = new PermitAllMatcherRegistry();
        if (!CollectionUtils.isEmpty(permitAllMatchers)) {
            for (PermitAllMatcher permitAllMatcher : permitAllMatchers) {
                registry.addPermitAllMatcher(permitAllMatcher);
            }
        }
        if (ssoClientConfigurer != null) {
            ssoClientConfigurer.addPermitAllMatcher(registry);
        }
        return registry;
    }

    @Bean
    @ConditionalOnMissingBean
    BasicAuthenticationRegistry basicAuthenticationRegistry() {
        BasicAuthenticationConfigurer configurer = new BasicAuthenticationConfigurer();
        for (BasicAuthenticationProperties.User user : basicAuthenticationProperties.getUsers()) {
            String username = user.getUsername();
            String password = user.getPassword();
            List<String> authorities = user.getAuthorities();
            configurer.addUser(username, password, authorities);
        }
        for (BasicAuthenticationProperties.Matcher requestMatcher : basicAuthenticationProperties.getRequestMatchers()) {
            String pattern = requestMatcher.getPattern();
            String httpMethod = requestMatcher.getHttpMethod();
            Boolean caseSensitive = requestMatcher.getCaseSensitive();
            List<String> authorities = requestMatcher.getAuthorities();
            if (pattern == null) {
                throw new NullPointerException("Pattern for basic request matcher cannot be null");
            }
            if (httpMethod == null) {
                throw new NullPointerException("Http method for basic request matcher cannot be null");
            }
            if (authorities.isEmpty()) {
                throw new IllegalArgumentException("At least one authority needs for request matcher");
            }
            if (caseSensitive == null) {
                caseSensitive = true;
                log.warn("Force case sensitive for {}", requestMatcher);
            }
            configurer.addRequestMatcher(pattern, httpMethod, caseSensitive, authorities.toArray(new String[0]));
        }
        if (ssoClientConfigurer != null) {
            ssoClientConfigurer.configureBasicAuthentication(configurer);
        }
        return configurer.buildRegistry();
    }

    @Bean
    @ConditionalOnMissingBean
    WebhookHandlerRegistry webhookHandlerRegistry(List<SsoClientWebhookHandler> ssoClientWebhookHandlers) {
        WebhookHandlerRegistry registry = new WebhookHandlerRegistry();
        if (!CollectionUtils.isEmpty(ssoClientWebhookHandlers)) {
            for (SsoClientWebhookHandler ssoClientWebhookHandler : ssoClientWebhookHandlers) {
                String id = ssoClientWebhookHandler.getId();
                registry.addWebhook(id, ssoClientWebhookHandler);
            }
        }
        if (ssoClientConfigurer != null) {
            ssoClientConfigurer.addWebhooks(registry);
        }
        return registry;
    }
}

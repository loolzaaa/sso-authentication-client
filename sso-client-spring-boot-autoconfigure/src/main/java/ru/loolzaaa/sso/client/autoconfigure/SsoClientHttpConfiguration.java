package ru.loolzaaa.sso.client.autoconfigure;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import ru.loolzaaa.sso.client.core.application.WebhookHandler;
import ru.loolzaaa.sso.client.core.security.matcher.SsoClientBasicAuthenticationBuilder;
import ru.loolzaaa.sso.client.core.security.matcher.SsoClientBasicAuthenticationRegistry;
import ru.loolzaaa.sso.client.core.security.matcher.SsoClientPermitAllMatcherHandler;
import ru.loolzaaa.sso.client.core.security.matcher.WebhookHandlerRegistry;

import java.util.List;

@Configuration(proxyBeanMethods =  false)
@Import({ SsoClientBasicConfiguration.class, SsoClientJwtConfiguration.class })
public class SsoClientHttpConfiguration {

    private static final Logger log = LogManager.getLogger(SsoClientHttpConfiguration.class.getName());

    private final BasicUsersProperties basicUsersProperties;

    public SsoClientHttpConfiguration(BasicUsersProperties basicUsersProperties) {
        this.basicUsersProperties = basicUsersProperties;
    }

    @Bean
    @ConditionalOnMissingBean
    SsoClientPermitAllMatcherHandler ssoClientPermitAllMatcherHandler() {
        return new SsoClientPermitAllMatcherHandler();
    }

    @Bean
    @ConditionalOnMissingBean
    SsoClientBasicAuthenticationBuilder ssoClientBasicMatcherHandlerBuilder() {
        SsoClientBasicAuthenticationBuilder builder = new SsoClientBasicAuthenticationBuilder();
        for (BasicUsersProperties.User user : basicUsersProperties.getUsers()) {
            String username = user.getUsername();
            String password = user.getPassword();
            List<String> authorities = user.getAuthorities();
            builder.addUser(username, password, authorities);
            log.info("Create basic user: {}", username);
        }
        for (BasicUsersProperties.Matcher requestMatcher : basicUsersProperties.getRequestMatchers()) {
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
                log.info("Force case sensitive for {}", requestMatcher);
            }
            builder.addRequestMatcher(pattern, httpMethod, caseSensitive, authorities.toArray(new String[0]));
            log.info("Add basic request matcher: {} {}. Allowed authorities: {}", httpMethod, pattern, authorities);
        }
        return builder;
    }

    @Bean
    @ConditionalOnMissingBean
    SsoClientBasicAuthenticationRegistry ssoClientBasicMatcherHandler(SsoClientBasicAuthenticationBuilder configurer) {
        return configurer.build();
    }

    @Bean
    @ConditionalOnMissingBean
    WebhookHandlerRegistry webhookHandlerRegistry(List<WebhookHandler> webhookHandlers) {
        WebhookHandlerRegistry registry = new WebhookHandlerRegistry();
        for (WebhookHandler webhookHandler : webhookHandlers) {
            String id = webhookHandler.getId();
            registry.addWebhook(id, webhookHandler);
            log.info("Register webhook: {}", id);
        }
        return registry;
    }
}

package ru.loolzaaa.sso.client.autoconfigure;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import ru.loolzaaa.sso.client.core.application.UserConfigTypeSupplier;
import ru.loolzaaa.sso.client.core.context.UserService;
import ru.loolzaaa.sso.client.core.endpoint.controller.SsoClientController;
import ru.loolzaaa.sso.client.core.endpoint.controller.SsoClientWebhookController;
import ru.loolzaaa.sso.client.core.endpoint.service.SsoClientService;
import ru.loolzaaa.sso.client.core.endpoint.service.SsoClientServiceImpl;
import ru.loolzaaa.sso.client.core.webhook.WebhookHandlerRegistry;

@AutoConfiguration(after = SsoClientAutoConfiguration.class)
public class SsoClientControllerAutoConfiguration {

    private static final Logger log = LogManager.getLogger(SsoClientControllerAutoConfiguration.class);

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnProperty(prefix = "sso.client", value = "endpoint.enable", havingValue = "true")
    static class SsoClientMainControllerConfiguration {
        @Bean
        @ConditionalOnMissingBean
        SsoClientService ssoClientService(UserService userService) {
            return new SsoClientServiceImpl(userService);
        }

        @Bean
        @ConditionalOnMissingBean
        SsoClientController ssoClientController(UserService userService,
                                                @Autowired(required = false) UserConfigTypeSupplier configTypeSupplier,
                                                ObjectMapper objectMapper) {
            SsoClientController ssoClientController = new SsoClientController(objectMapper, ssoClientService(userService), configTypeSupplier);
            log.info("Sso Client endpoint and it description available at '/sso/client'");
            return ssoClientController;
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnProperty(prefix = "sso.client", value = "webhook.enable", havingValue = "true")
    public static class SsoClientWebhookConfiguration {
        @Bean
        @ConditionalOnMissingBean
        SsoClientWebhookController ssoClientWebhookController(WebhookHandlerRegistry registry) {
            SsoClientWebhookController ssoClientWebhookController = new SsoClientWebhookController(registry);
            log.info("Sso Client webhooks processor available at '/sso/webhook'");
            return ssoClientWebhookController;
        }
    }
}

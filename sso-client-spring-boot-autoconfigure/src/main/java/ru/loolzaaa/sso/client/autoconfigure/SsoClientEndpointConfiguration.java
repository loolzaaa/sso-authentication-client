package ru.loolzaaa.sso.client.autoconfigure;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import ru.loolzaaa.sso.client.core.context.UserService;
import ru.loolzaaa.sso.client.core.endpoint.controller.SsoClientController;
import ru.loolzaaa.sso.client.core.endpoint.controller.SsoClientWebhookController;
import ru.loolzaaa.sso.client.core.endpoint.service.SsoClientService;
import ru.loolzaaa.sso.client.core.endpoint.service.SsoClientServiceImpl;
import ru.loolzaaa.sso.client.core.security.matcher.WebhookHandlerRegistry;

@Configuration(proxyBeanMethods =  false)
@ConditionalOnProperty(prefix = "sso.client", value = "endpoint.enable", havingValue = "true")
public class SsoClientEndpointConfiguration {

    private static final Log log = LogFactory.getLog(SsoClientEndpointConfiguration.class);

    @Bean
    @ConditionalOnMissingBean
    SsoClientService ssoClientService(UserService userService) {
        return new SsoClientServiceImpl(userService);
    }

    @Bean
    @ConditionalOnMissingBean
    SsoClientController ssoClientController(UserService userService) {
        SsoClientController ssoClientController = new SsoClientController(ssoClientService(userService));
        log.info("Sso Client endpoint and it description available at '/sso'");
        return ssoClientController;
    }

    @Bean
    @ConditionalOnMissingBean
    SsoClientWebhookController ssoClientWebhookController(WebhookHandlerRegistry registry) {
        return new SsoClientWebhookController(registry);
    }
}

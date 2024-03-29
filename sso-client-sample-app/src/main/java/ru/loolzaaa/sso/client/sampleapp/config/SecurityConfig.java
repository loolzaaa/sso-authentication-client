package ru.loolzaaa.sso.client.sampleapp.config;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.stereotype.Component;
import ru.loolzaaa.sso.client.core.application.SsoClientApplicationRegister;
import ru.loolzaaa.sso.client.core.application.SsoClientLogoutHandler;
import ru.loolzaaa.sso.client.core.application.UserConfigTypeSupplier;
import ru.loolzaaa.sso.client.core.config.SsoClientConfigurer;
import ru.loolzaaa.sso.client.core.model.UserPrincipal;
import ru.loolzaaa.sso.client.core.security.basic.BasicAuthenticationConfigurer;
import ru.loolzaaa.sso.client.core.security.permitall.PermitAllMatcherRegistry;
import ru.loolzaaa.sso.client.core.webhook.WebhookHandlerRegistry;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Set;

@Configuration
public class SecurityConfig implements WebSecurityCustomizer, SsoClientConfigurer {

    @Bean
    UserConfigTypeSupplier userConfigTypeSupplier() {
        return () -> UserConfig.class;
    }

    @Bean
    AccessDeniedHandler accessDeniedHandler() {
        AccessDeniedHandlerImpl accessDeniedHandler = new AccessDeniedHandlerImpl();
        accessDeniedHandler.setErrorPage("/forbidden");
        return accessDeniedHandler;
    }

    @Override
    public void customize(WebSecurity web) {
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Override
    public void addPermitAllMatcher(PermitAllMatcherRegistry registry) {
        registry.addPermitAllMatcher(HttpMethod.GET, true, "/api/time");
    }

    @Override
    public void configureBasicAuthentication(BasicAuthenticationConfigurer configurer) {
        configurer
                .addUser("test", "test", Set.of("test"))
                .addRequestMatcher("/api/get/basic2/**", new String[]{"test"});
    }

    @Override
    public void addWebhooks(WebhookHandlerRegistry registry) {
        registry.addWebhook("WEBHOOK_VIA_CONFIG", "PASSWORD", System.err::println);
    }

    @Component
    static class ApplicationRegister implements SsoClientApplicationRegister {
        @Override
        public void register(UserPrincipal userPrincipal) {
            System.out.println("---------   Hello from application register hook!   ---------");
            ///////////////////////////////////////////////
            //
            // Application-specific actions for register ...
            //
            ///////////////////////////////////////////////
        }
    }

    @Component
    static class CustomLogoutHandler implements SsoClientLogoutHandler {
        @Override
        public void logout(HttpServletRequest req, HttpServletResponse resp, Authentication auth) {
            System.out.println("---------   Hello from custom logout handler!   ---------");
            ///////////////////////////////////////////////
            //
            // Application-specific logout ...
            //
            ///////////////////////////////////////////////
        }
    }
}

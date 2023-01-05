package ru.loolzaaa.sso.client.sampleapp.config;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import ru.loolzaaa.sso.client.core.application.SsoClientApplicationRegister;
import ru.loolzaaa.sso.client.core.application.SsoClientLogoutHandler;
import ru.loolzaaa.sso.client.core.model.UserPrincipal;
import ru.loolzaaa.sso.client.core.security.matcher.SsoClientBasicAuthenticationBuilder;
import ru.loolzaaa.sso.client.core.security.matcher.SsoClientBasicAuthenticationRegistry;
import ru.loolzaaa.sso.client.core.security.matcher.SsoClientPermitAllMatcherHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Set;

@Configuration
public class SecurityConfig implements WebSecurityCustomizer {

    @Override
    public void customize(WebSecurity web) {
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    SsoClientPermitAllMatcherHandler ssoClientPermitAllMatcherHandler() {
        SsoClientPermitAllMatcherHandler permitAllMatcherHandler = new SsoClientPermitAllMatcherHandler();
        permitAllMatcherHandler.addPermitAllMatcher(HttpMethod.GET, true, "/api/time");
        return permitAllMatcherHandler;
    }

    @Bean
    SsoClientBasicAuthenticationRegistry ssoClientBasicMatcherHandler(SsoClientBasicAuthenticationBuilder basicAuthenticationBuilder) {
        return basicAuthenticationBuilder
                .addUser("test", "test", Set.of("test"))
                .addRequestMatcher("/api/get/basic2/**", new String[]{"test"})
                .build();
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
    public class CustomLogoutHandler implements SsoClientLogoutHandler {
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

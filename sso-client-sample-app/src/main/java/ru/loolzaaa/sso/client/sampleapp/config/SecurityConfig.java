package ru.loolzaaa.sso.client.sampleapp.config;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import ru.loolzaaa.sso.client.core.helper.SsoClientApplicationRegister;
import ru.loolzaaa.sso.client.core.helper.SsoClientLogoutHandler;
import ru.loolzaaa.sso.client.core.model.UserPrincipal;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Configuration
public class SecurityConfig implements WebSecurityCustomizer {

    @Override
    public void customize(WebSecurity web) {
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
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

package ru.loolzaaa.sso.client.sampleapp.config;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.stereotype.Component;
import ru.loolzaaa.sso.client.autoconfigure.SsoClientHttpConfigurer;
import ru.loolzaaa.sso.client.core.helper.SsoClientApplicationRegister;
import ru.loolzaaa.sso.client.core.model.UserPrincipal;

@RequiredArgsConstructor
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final SsoClientHttpConfigurer ssoClientHttpConfigurer;

    private final CustomLogoutHandler customLogoutHandler;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .apply(ssoClientHttpConfigurer)
                .and()
                .logout()
                    .addLogoutHandler(customLogoutHandler);
    }

    @Override
    public void configure(WebSecurity web) {
        web
                .ignoring()
                    .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Component
    static class ApplicationRegister implements SsoClientApplicationRegister {
        @Override
        public void register(UserPrincipal userPrincipal) {
            System.out.println("---------   Hello from application register hook!   ---------");
        }
    }
}

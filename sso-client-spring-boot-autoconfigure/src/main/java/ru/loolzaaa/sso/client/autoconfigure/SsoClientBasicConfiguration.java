package ru.loolzaaa.sso.client.autoconfigure;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import ru.loolzaaa.sso.client.core.security.basic.BasicAuthenticationRegistry;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@Configuration
@ConditionalOnProperty(prefix = "sso.client.basic", name = "enable", havingValue = "true")
public class SsoClientBasicConfiguration {

    private static final Logger log = LogManager.getLogger(SsoClientBasicConfiguration.class.getName());

    private final BasicAuthenticationProperties basicAuthenticationProperties;

    private final BasicAuthenticationRegistry basicAuthenticationRegistry;

    public SsoClientBasicConfiguration(BasicAuthenticationProperties basicAuthenticationProperties,
                                       BasicAuthenticationRegistry basicAuthenticationRegistry) {
        this.basicAuthenticationProperties = basicAuthenticationProperties;
        this.basicAuthenticationRegistry = basicAuthenticationRegistry;
    }

    @Bean
    public InMemoryUserDetailsManager inMemoryUserDetailsManager() {
        if (basicAuthenticationRegistry.getUsers().isEmpty()) {
            log.warn("Basic authentication was enabled, but there is no users for it");
        }
        List<UserDetails> userDetailsList = new ArrayList<>(basicAuthenticationRegistry.getUsers().size());
        for (BasicAuthenticationRegistry.User user : basicAuthenticationRegistry.getUsers()) {
            userDetailsList.add(User
                    .withUsername(user.getUsername())
                    .password(basicPasswordEncoder().encode(user.getPassword()))
                    .authorities(user.getAuthorities())
                    .build());
            log.info("Register basic user: {}", user.getUsername());
        }
        return new InMemoryUserDetailsManager(userDetailsList);
    }

    @Order(1)
    @Bean
    public SecurityFilterChain basicFilterChain(HttpSecurity http) throws Exception {
        Set<AntPathRequestMatcher> requestMatchers = basicAuthenticationRegistry.getRequestMatcherAuthoritiesMap().keySet();
        if (requestMatchers.isEmpty()) {
            throw new InstantiationException("Basic authentication was enabled, but there is no request matchers for it!");
        }
        for (AntPathRequestMatcher requestMatcher : requestMatchers) {
            http.requestMatchers(configurer -> configurer.requestMatchers(requestMatcher));
        }
        log.info("Basic authentication configured for: {}", requestMatchers);
        http
                .userDetailsService(inMemoryUserDetailsManager())
                .csrf().disable()
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        for (AntPathRequestMatcher requestMatcher : requestMatchers) {
            String[] authorities = basicAuthenticationRegistry.getRequestMatcherAuthoritiesMap().get(requestMatcher);
            http.authorizeHttpRequests(authorize -> authorize
                    .requestMatchers(requestMatcher).hasAnyAuthority(authorities));
            log.info("Basic request matcher {} authorized for: {}", requestMatcher, authorities);
        }
        http
                .httpBasic(httpBasic -> httpBasic
                        .realmName(basicAuthenticationProperties.getRealmName()))
                .anonymous().disable();
        log.info("Basic configuration completed");
        return http.build();
    }

    @Bean
    @ConditionalOnMissingBean
    PasswordEncoder basicPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

package ru.loolzaaa.sso.client.autoconfigure;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.access.intercept.RequestMatcherDelegatingAuthorizationManager;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import ru.loolzaaa.sso.client.core.application.SsoClientApplicationRegister;
import ru.loolzaaa.sso.client.core.application.SsoClientLogoutHandler;
import ru.loolzaaa.sso.client.core.context.UserService;
import ru.loolzaaa.sso.client.core.security.CookieName;
import ru.loolzaaa.sso.client.core.security.DefaultAuthenticationEntryPoint;
import ru.loolzaaa.sso.client.core.security.DefaultLogoutSuccessHandler;
import ru.loolzaaa.sso.client.core.security.filter.JwtTokenFilter;
import ru.loolzaaa.sso.client.core.security.filter.QueryJwtTokenFilter;
import ru.loolzaaa.sso.client.core.security.matcher.PermitAllMatcher;
import ru.loolzaaa.sso.client.core.security.matcher.PermitAllMatcherRegistry;
import ru.loolzaaa.sso.client.core.util.JWTUtils;

import java.util.List;

@Configuration
public class SsoClientJwtConfiguration {

    private static final Logger log = LogManager.getLogger(SsoClientJwtConfiguration.class.getName());

    private final SsoClientProperties properties;

    private final DefaultAuthenticationEntryPoint authenticationEntryPoint;
    private final DefaultLogoutSuccessHandler logoutSuccessHandler;
    private final QueryJwtTokenFilter queryJwtTokenFilter;
    private final JwtTokenFilter jwtTokenFilter;

    public SsoClientJwtConfiguration(SsoClientProperties properties,
                                     DefaultAuthenticationEntryPoint authenticationEntryPoint,
                                     DefaultLogoutSuccessHandler logoutSuccessHandler,
                                     JWTUtils jwtUtils,
                                     UserService userService,
                                     List<SsoClientApplicationRegister> ssoClientApplicationRegisters) {
        if (!UrlUtils.isAbsoluteUrl(properties.getEntryPointAddress())) {
            throw new IllegalArgumentException("SSO Server entrypoint must be absolute url");
        }
        JwtTokenFilter jwtTokenFilter = new JwtTokenFilter(
                properties.getEntryPointAddress(),
                properties.getRefreshTokenUri(),
                jwtUtils,
                userService);
        jwtTokenFilter.addApplicationRegisters(ssoClientApplicationRegisters);

        QueryJwtTokenFilter queryJwtTokenFilter = new QueryJwtTokenFilter(jwtUtils);

        this.properties = properties;
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.logoutSuccessHandler = logoutSuccessHandler;
        this.queryJwtTokenFilter = queryJwtTokenFilter;
        this.jwtTokenFilter = jwtTokenFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   PermitAllMatcherRegistry permitAllMatcherRegistry,
                                                   List<SsoClientLogoutHandler> logoutHandlers) throws Exception {
        http
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .ignoringAntMatchers("/sso/webhook/**"))
                .cors()
                .and()
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint(authenticationEntryPoint))
                .logout(logout -> logout
                        .logoutRequestMatcher(new AntPathRequestMatcher("/do_logout", "POST"))
                        .logoutSuccessHandler(logoutSuccessHandler)
                        .deleteCookies("JSESSIONID", CookieName.ACCESS.getName(), CookieName.RFID.getName())
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .permitAll())
                .httpBasic().disable()
                .formLogin().disable()
                .anonymous().disable()
                // Filters order is important!
                .addFilterBefore(queryJwtTokenFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class);

        if (!permitAllMatcherRegistry.getMatchers().isEmpty()) {
            final AuthorizationManager<RequestAuthorizationContext> permitAllAuthorizationManager =
                    (a, o) -> new AuthorizationDecision(true);
            RequestMatcherDelegatingAuthorizationManager.Builder authorizationManagerBuilder =
                    RequestMatcherDelegatingAuthorizationManager.builder();
            for (PermitAllMatcher matcher : permitAllMatcherRegistry.getMatchers()) {
                if (matcher.isIgnoreCsrf()) {
                    http.csrf(csrf -> csrf.ignoringRequestMatchers(matcher.getRequestMatcher()));
                }
                http.authorizeHttpRequests(authorize -> {
                    authorize.requestMatchers(matcher.getRequestMatcher()).permitAll();
                    authorizationManagerBuilder.add(matcher.getRequestMatcher(), permitAllAuthorizationManager);
                });
                log.info("Add permit all matcher: {}", matcher);
            }
            jwtTokenFilter.setPermitAllAuthorizationManager(authorizationManagerBuilder.build());
        }
        http.authorizeHttpRequests(authorize -> authorize
                .antMatchers(HttpMethod.POST, "/sso/webhook/**").permitAll()
                .anyRequest().hasAuthority(properties.getApplicationName()));

        if (logoutHandlers != null && !logoutHandlers.isEmpty()) {
            for (SsoClientLogoutHandler logoutHandler : logoutHandlers) {
                http.logout(logout -> logout
                        .addLogoutHandler(logoutHandler));
                log.info("Add custom logout handler: {}", logoutHandler);
            }
        }

        log.info("SSO Client HttpSecurity configuration completed");
        return http.build();
    }
}

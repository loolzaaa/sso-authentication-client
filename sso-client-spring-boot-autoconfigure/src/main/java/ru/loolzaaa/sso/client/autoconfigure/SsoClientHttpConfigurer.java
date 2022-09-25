package ru.loolzaaa.sso.client.autoconfigure;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.savedrequest.NullRequestCache;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import ru.loolzaaa.sso.client.core.filter.JwtTokenFilter;
import ru.loolzaaa.sso.client.core.filter.QueryJwtTokenFilter;
import ru.loolzaaa.sso.client.core.security.CookieName;
import ru.loolzaaa.sso.client.core.security.DefaultSsoClientAuthenticationEntryPoint;
import ru.loolzaaa.sso.client.core.security.DefaultSsoClientLogoutSuccessHandler;

public class SsoClientHttpConfigurer extends AbstractHttpConfigurer<SsoClientHttpConfigurer, HttpSecurity> {

    private final SsoClientProperties properties;

    private final DefaultSsoClientAuthenticationEntryPoint authenticationEntryPoint;
    private final DefaultSsoClientLogoutSuccessHandler logoutSuccessHandler;
    private final QueryJwtTokenFilter queryJwtTokenFilter;
    private final JwtTokenFilter jwtTokenFilter;

    public SsoClientHttpConfigurer(SsoClientProperties properties,
                                   DefaultSsoClientAuthenticationEntryPoint authenticationEntryPoint,
                                   DefaultSsoClientLogoutSuccessHandler logoutSuccessHandler,
                                   QueryJwtTokenFilter queryJwtTokenFilter,
                                   JwtTokenFilter jwtTokenFilter) {
        this.properties = properties;
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.logoutSuccessHandler = logoutSuccessHandler;
        this.queryJwtTokenFilter = queryJwtTokenFilter;
        this.jwtTokenFilter = jwtTokenFilter;
    }

    @Override
    public void init(HttpSecurity http) throws Exception {
        http
                .csrf()
                    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .and()
                .cors()
                .and()
                    .securityContext()
                        .securityContextRepository(new NullSecurityContextRepository())
                .and()
                    .requestCache()
                        .requestCache(new NullRequestCache())
                .and()
                    .authorizeRequests()
                        .anyRequest()
                            .hasAuthority(properties.getApplicationName())
                .and()
                    .exceptionHandling()
                        .authenticationEntryPoint(authenticationEntryPoint)
                .and()
                    .httpBasic()
                        .disable()
                    .formLogin()
                        .disable()
                    .logout()
                        .logoutRequestMatcher(new AntPathRequestMatcher("/do_logout", "POST"))
                        .logoutSuccessHandler(logoutSuccessHandler)
                        .deleteCookies("JSESSIONID", CookieName.ACCESS.getName(), CookieName.RFID.getName())
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .permitAll()
                .and()
                // Filters order is important!
                .addFilterBefore(queryJwtTokenFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class);
    }
}

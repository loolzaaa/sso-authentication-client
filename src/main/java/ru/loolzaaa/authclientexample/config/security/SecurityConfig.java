package ru.loolzaaa.authclientexample.config.security;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import ru.loolzaaa.authclientexample.config.security.bean.CustomAuthenticationEntryPoint;
import ru.loolzaaa.authclientexample.config.security.bean.CustomLogoutHandler;
import ru.loolzaaa.authclientexample.config.security.bean.CustomLogoutSuccessHandler;
import ru.loolzaaa.authclientexample.config.security.filter.JwtTokenFilter;
import ru.loolzaaa.authclientexample.config.security.filter.QueryJwtTokenFilter;
import ru.loolzaaa.authclientexample.services.UserService;

import java.util.List;

@RequiredArgsConstructor
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${auth.application.name}")
    private String applicationName;
    @Value("${auth.refresh.token.uri}")
    private String refreshTokenURI;

    public static final String ENTRY_POINT_ADDR = "http://localhost:9999";
    public static final String ENTRY_POINT_URI = "/login";

    private final JWTUtils jwtUtils;

    private final UserService userService;

    private final CustomLogoutHandler customLogoutHandler;
    private final CustomLogoutSuccessHandler customLogoutSuccessHandler;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf()
                    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .and()
                .cors()
                .and()
                    .authorizeRequests()
                    .anyRequest()
                        .hasAuthority(applicationName)
                .and()
                    .exceptionHandling()
                        .authenticationEntryPoint(new CustomAuthenticationEntryPoint(ENTRY_POINT_ADDR + ENTRY_POINT_URI))
                .and()
                    .httpBasic()
                        .disable()
                    .formLogin()
                        .disable()
                    .logout()
                        .logoutRequestMatcher(new AntPathRequestMatcher("/do_logout", "POST"))
                        .addLogoutHandler(customLogoutHandler)
                        .logoutSuccessHandler(customLogoutSuccessHandler)
                        .deleteCookies("JSESSIONID", "_t_access", "_t_refresh", "_t_rfid")
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .permitAll()
                .and()
                // Filters order is important!
                .addFilterBefore(new QueryJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new JwtTokenFilter(refreshTokenURI, jwtUtils, userService), UsernamePasswordAuthenticationFilter.class);
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web
                .ignoring()
                    .antMatchers("/webjars/**", "/js/**", "/css/**", "/images/**", "/favicon.*");
    }

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.setAllowedOriginPatterns(List.of("http://localhost:[*]"));
        config.setAllowedMethods(List.of("GET", "HEAD", "POST"));
        config.addAllowedHeader("*");
        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }
}

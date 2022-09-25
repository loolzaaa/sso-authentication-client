package ru.loolzaaa.sso.client.autoconfigure;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import ru.loolzaaa.sso.client.core.JWTUtils;
import ru.loolzaaa.sso.client.core.UserService;
import ru.loolzaaa.sso.client.core.filter.JwtTokenFilter;
import ru.loolzaaa.sso.client.core.filter.QueryJwtTokenFilter;
import ru.loolzaaa.sso.client.core.helper.SsoClientApplicationRegister;
import ru.loolzaaa.sso.client.core.helper.SsoClientLogoutHandler;
import ru.loolzaaa.sso.client.core.security.CookieName;
import ru.loolzaaa.sso.client.core.security.DefaultSsoClientAuthenticationEntryPoint;
import ru.loolzaaa.sso.client.core.security.DefaultSsoClientLogoutSuccessHandler;

import java.util.List;

@Configuration(proxyBeanMethods =  false)
public class SsoClientHttpConfiguration {

    private static final Logger log = LogManager.getLogger(SsoClientHttpConfiguration.class.getName());

    private final SsoClientProperties properties;

    private final DefaultSsoClientAuthenticationEntryPoint authenticationEntryPoint;
    private final DefaultSsoClientLogoutSuccessHandler logoutSuccessHandler;
    private final QueryJwtTokenFilter queryJwtTokenFilter;
    private final JwtTokenFilter jwtTokenFilter;

    public SsoClientHttpConfiguration(SsoClientProperties properties,
                                      DefaultSsoClientAuthenticationEntryPoint authenticationEntryPoint,
                                      DefaultSsoClientLogoutSuccessHandler logoutSuccessHandler,
                                      JWTUtils jwtUtils,
                                      UserService userService,
                                      List<SsoClientApplicationRegister> ssoClientApplicationRegisters) {
        //        JwtTokenFilter jwtTokenFilter = new JwtTokenFilter(properties.getEntryPointAddress(), properties.getRefreshTokenUri(),
//                anonymousProperties.getKey(), anonymousProperties.getPrincipal(), anonymousProperties.getAuthorities(),
//                jwtUtils, userService, webInvocationPrivilegeEvaluator);
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
                                                   List<SsoClientLogoutHandler> logoutHandlers) throws Exception {
        http
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
                .cors()
                .and()
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().hasAuthority(properties.getApplicationName()))
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

        if (logoutHandlers != null && !logoutHandlers.isEmpty()) {
            for (SsoClientLogoutHandler logoutHandler : logoutHandlers) {
                http.logout().addLogoutHandler(logoutHandler);
                log.info("Add custom logout handler: " + logoutHandler);
            }
        }

        log.info("SSO Client HttpSecurity configuration completed");
        return http.build();
    }

//    @Override
//    public void init(HttpSecurity http) throws Exception {
//        http
//                .csrf()
//                    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                .and()
//                .cors()
//                .and()
//                    .securityContext()
//                        .securityContextRepository(new NullSecurityContextRepository())
//                .and()
//                    .requestCache()
//                        .requestCache(new NullRequestCache())
//                .and()
//                    .authorizeRequests()
//                        .anyRequest()
//                            .hasAuthority(properties.getApplicationName())
//                .and()
//                    .exceptionHandling()
//                        .authenticationEntryPoint(authenticationEntryPoint)
//                .and()
//                    .httpBasic()
//                        .disable()
//                    .formLogin()
//                        .disable()
//                    .logout()
//                        .logoutRequestMatcher(new AntPathRequestMatcher("/do_logout", "POST"))
//                        .logoutSuccessHandler(logoutSuccessHandler)
//                        .deleteCookies("JSESSIONID", CookieName.ACCESS.getName(), CookieName.RFID.getName())
//                        .invalidateHttpSession(true)
//                        .clearAuthentication(true)
//                        .permitAll()
//                .and()
//                // Filters order is important!
//                .addFilterBefore(queryJwtTokenFilter, UsernamePasswordAuthenticationFilter.class)
//                .addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class);
//    }
}

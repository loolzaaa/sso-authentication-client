package ru.loolzaaa.sso.client.autoconfigure;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import ru.loolzaaa.sso.client.core.JWTUtils;
import ru.loolzaaa.sso.client.core.UserService;
import ru.loolzaaa.sso.client.core.filter.JwtTokenFilter;
import ru.loolzaaa.sso.client.core.filter.QueryJwtTokenFilter;

import java.util.List;

@Configuration(proxyBeanMethods =  false)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class SsoClientFilterConfiguration {

    private final JWTUtils jwtUtils;
    private final UserService userService;

    public SsoClientFilterConfiguration(JWTUtils jwtUtils, UserService userService) {
        this.jwtUtils = jwtUtils;
        this.userService = userService;
    }

    @Bean
    @ConditionalOnMissingBean
    QueryJwtTokenFilter queryJwtTokenFilter() {
        return new QueryJwtTokenFilter(jwtUtils);
    }

    @Bean
    @ConditionalOnMissingBean
    JwtTokenFilter jwtTokenFilter(SsoClientProperties properties) {
        return new JwtTokenFilter(properties.getEntryPointAddress(), properties.getRefreshTokenUri(), jwtUtils, userService);
    }

    @Bean
    @ConditionalOnMissingBean
    CorsFilter corsFilter() {
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

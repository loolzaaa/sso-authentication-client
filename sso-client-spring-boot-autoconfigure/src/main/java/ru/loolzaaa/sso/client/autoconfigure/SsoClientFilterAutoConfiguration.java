package ru.loolzaaa.sso.client.autoconfigure;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.List;

@AutoConfiguration(after = SsoClientAutoConfiguration.class)
public class SsoClientFilterAutoConfiguration {

    private static final Logger log = LogManager.getLogger(SsoClientFilterAutoConfiguration.class);

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
        log.info("Register default CORS configuration: {}", config);
        return new CorsFilter(source);
    }
}

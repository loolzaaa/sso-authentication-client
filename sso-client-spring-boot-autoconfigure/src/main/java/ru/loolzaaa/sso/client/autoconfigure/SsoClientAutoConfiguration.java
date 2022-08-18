package ru.loolzaaa.sso.client.autoconfigure;

import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.RestTemplate;
import ru.loolzaaa.sso.client.core.JWTUtils;
import ru.loolzaaa.sso.client.core.UserService;
import ru.loolzaaa.sso.client.core.context.UserStore;
import ru.loolzaaa.sso.client.core.filter.JwtTokenFilter;
import ru.loolzaaa.sso.client.core.filter.QueryJwtTokenFilter;
import ru.loolzaaa.sso.client.core.helper.SsoClientTokenDataReceiver;
import ru.loolzaaa.sso.client.core.security.DefaultSsoClientAuthenticationEntryPoint;
import ru.loolzaaa.sso.client.core.security.DefaultSsoClientLogoutSuccessHandler;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(SsoClientProperties.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix = "sso.client", value = { "applicationName", "entryPointAddress", "entryPointUri" })
@AutoConfigureAfter(SecurityAutoConfiguration.class)
@Import({ SsoClientFilterConfiguration.class, SsoClientEndpointConfiguration.class })
public class SsoClientAutoConfiguration {

    private final SsoClientProperties properties;

    public SsoClientAutoConfiguration(SsoClientProperties properties) {
        this.properties = properties;
    }

    @Bean
    @ConditionalOnMissingBean
    SsoClientHttpConfigurer ssoClientHttpConfigurer(DefaultSsoClientAuthenticationEntryPoint authenticationEntryPoint,
                                                    DefaultSsoClientLogoutSuccessHandler logoutSuccessHandler,
                                                    QueryJwtTokenFilter queryJwtTokenFilter,
                                                    JwtTokenFilter jwtTokenFilter) {
        return new SsoClientHttpConfigurer(properties, authenticationEntryPoint, logoutSuccessHandler,
                queryJwtTokenFilter, jwtTokenFilter);
    }

    @Bean
    @ConditionalOnMissingBean
    DefaultSsoClientAuthenticationEntryPoint authenticationEntryPoint() {
        String loginFormUrl = properties.getEntryPointAddress() + properties.getEntryPointUri();
        return new DefaultSsoClientAuthenticationEntryPoint(loginFormUrl);
    }

    @Bean
    @ConditionalOnMissingBean
    DefaultSsoClientLogoutSuccessHandler logoutSuccessHandler(RestTemplateBuilder restTemplateBuilder, UserService userService) {
        String entryPointAddress = properties.getEntryPointAddress();
        String basicLogin = properties.getBasicLogin();
        String basicPassword = properties.getBasicPassword();

        //TODO: Make more settings for rest template
        final RestTemplate restTemplate = restTemplateBuilder.build();

        return new DefaultSsoClientLogoutSuccessHandler(entryPointAddress, basicLogin, basicPassword, userService, restTemplate);
    }

    @Bean
    @ConditionalOnMissingBean
    UserService userService(RestTemplateBuilder restTemplateBuilder, UserStore userStore, JWTUtils jwtUtils) {
        String applicationName = properties.getApplicationName();
        String entryPointAddress = properties.getEntryPointAddress();
        String basicLogin = properties.getBasicLogin();
        String basicPassword = properties.getBasicPassword();

        //TODO: Make more settings for rest template
        final RestTemplate restTemplate = restTemplateBuilder.build();

        return new UserService(applicationName, entryPointAddress, basicLogin, basicPassword,
                restTemplate, userStore, jwtUtils);
    }

    @Bean
    @ConditionalOnMissingBean
    UserStore userStore() {
        return new UserStore();
    }

    @Bean
    @ConditionalOnMissingBean
    JWTUtils jwtUtils() {
        return new JWTUtils();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "sso.client.receiver", value = { "username", "password" })
    SsoClientTokenDataReceiver ssoClientTokenDataReceiver() {
        String entryPointAddress = properties.getEntryPointAddress();
        String username = properties.getReceiver().getUsername();
        String password = properties.getReceiver().getPassword();
        String fingerprint = properties.getReceiver().getFingerprint();
        return new SsoClientTokenDataReceiver(jwtUtils(), entryPointAddress, username, password, fingerprint);
    }
}


package ru.loolzaaa.sso.client.autoconfigure;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;
import ru.loolzaaa.sso.client.core.context.UserService;
import ru.loolzaaa.sso.client.core.context.UserStore;
import ru.loolzaaa.sso.client.core.security.CookieName;
import ru.loolzaaa.sso.client.core.security.DefaultAuthenticationEntryPoint;
import ru.loolzaaa.sso.client.core.security.DefaultLogoutSuccessHandler;
import ru.loolzaaa.sso.client.core.security.token.TokenDataReceiver;
import ru.loolzaaa.sso.client.core.util.JWTUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

@AutoConfiguration(
        before = { SecurityAutoConfiguration.class },
        beforeName = "org.springframework.boot.actuate.autoconfigure.security.servlet.ManagementWebSecurityAutoConfiguration"
)
@EnableConfigurationProperties({ SsoClientProperties.class, BasicAuthenticationProperties.class })
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix = "sso.client", value = { "applicationName", "entryPointAddress", "entryPointUri" })
@Import({ SsoClientConfiguration.class })
public class SsoClientAutoConfiguration {

    private static final Logger log = LogManager.getLogger(SsoClientAutoConfiguration.class.getName());

    private final SsoClientProperties properties;

    public SsoClientAutoConfiguration(SsoClientProperties properties) {
        this.properties = properties;
    }

    @Bean
    @ConditionalOnMissingBean
    DefaultAuthenticationEntryPoint authenticationEntryPoint() {
        StringBuilder loginFormUrlBuilder = new StringBuilder();
        if (!UrlUtils.isAbsoluteUrl(properties.getEntryPointAddress())) {
            throw new IllegalArgumentException("SSO Server entrypoint must be absolute url");
        }
        loginFormUrlBuilder.append(properties.getEntryPointAddress());
        if (properties.getEntryPointAddress().endsWith("/")) {
            loginFormUrlBuilder.deleteCharAt(loginFormUrlBuilder.length());
        }
        if (!properties.getEntryPointUri().startsWith("/")) {
            loginFormUrlBuilder.append("/");
        }
        loginFormUrlBuilder.append(properties.getEntryPointUri());
        return new DefaultAuthenticationEntryPoint(loginFormUrlBuilder.toString());
    }

    @Bean
    @ConditionalOnMissingBean
    DefaultLogoutSuccessHandler logoutSuccessHandler(RestTemplateBuilder restTemplateBuilder) {
        if (!UrlUtils.isAbsoluteUrl(properties.getEntryPointAddress())) {
            throw new IllegalArgumentException("SSO Server entrypoint must be absolute url");
        }
        String entryPointAddress = properties.getEntryPointAddress();
        String login = properties.getRevokeUsername();
        String password = properties.getRevokePassword();

        final RestTemplate restTemplate = restTemplateBuilder
                .basicAuthentication(login, password, StandardCharsets.US_ASCII)
                .setConnectTimeout(Duration.ofSeconds(4L))
                .setReadTimeout(Duration.ofSeconds(4L))
                .build();

        return new DefaultLogoutSuccessHandler(entryPointAddress, restTemplate);
    }

    @Bean
    @ConditionalOnMissingBean
    UserService userService(RestTemplateBuilder restTemplateBuilder, UserStore userStore, JWTUtils jwtUtils,
                            @Autowired(required = false) TokenDataReceiver tokenDataReceiver) {
        String applicationName = properties.getApplicationName();
        String entryPointAddress = properties.getEntryPointAddress();
        String basicLogin = properties.getBasicLogin();
        String basicPassword = properties.getBasicPassword();

        restTemplateBuilder = restTemplateBuilder
                .setConnectTimeout(Duration.ofSeconds(4L))
                .setReadTimeout(Duration.ofSeconds(4L))
                .requestFactory(HttpComponentsClientHttpRequestFactory::new);
        if (tokenDataReceiver != null) {
            log.info("SSO Client User service configured with TokenDataReceiver");
            restTemplateBuilder = restTemplateBuilder.additionalInterceptors(new RestTemplateTokenInterceptor(tokenDataReceiver));
        } else {
            log.info("SSO Client User service configured with Basic Authentication");
            restTemplateBuilder = restTemplateBuilder.basicAuthentication(basicLogin, basicPassword, StandardCharsets.US_ASCII);
        }
        RestTemplate restTemplate = restTemplateBuilder.build();

        return new UserService(
                applicationName,
                entryPointAddress,
                restTemplate,
                userStore,
                jwtUtils,
                tokenDataReceiver != null);
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
    TokenDataReceiver tokenDataReceiver() {
        if (!UrlUtils.isAbsoluteUrl(properties.getEntryPointAddress())) {
            throw new IllegalArgumentException("SSO Server entrypoint must be absolute url");
        }
        String entryPointAddress = properties.getEntryPointAddress();
        String username = properties.getReceiver().getUsername();
        String password = properties.getReceiver().getPassword();
        String fingerprint = properties.getReceiver().getFingerprint();
        if (!StringUtils.hasText(fingerprint)) {
            log.warn("For production purposes fingerprint must be non-blank/empty string. Current fingerprint: {}", fingerprint);
        }
        return new TokenDataReceiver(jwtUtils(), entryPointAddress, username, password, fingerprint);
    }

    private static class RestTemplateTokenInterceptor implements ClientHttpRequestInterceptor {

        private final TokenDataReceiver tokenDataReceiver;

        public RestTemplateTokenInterceptor(TokenDataReceiver tokenDataReceiver) {
            this.tokenDataReceiver = tokenDataReceiver;
        }

        @Override
        public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {
            tokenDataReceiver.getTokenDataLock().lock();
            try {
                tokenDataReceiver.updateData();
                request.getHeaders().add("Cookie", "XSRF-TOKEN=" + tokenDataReceiver.getCsrfToken());
                request.getHeaders().add("Cookie", CookieName.ACCESS.getName() + "=" + tokenDataReceiver.getAccessToken());
                request.getHeaders().add("X-XSRF-TOKEN", tokenDataReceiver.getCsrfToken().toString());
            } finally {
                tokenDataReceiver.getTokenDataLock().unlock();
            }
            return execution.execute(request, body);
        }
    }
}


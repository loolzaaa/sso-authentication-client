package ru.loolzaaa.sso.client.core.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class DefaultAuthenticationEntryPoint extends LoginUrlAuthenticationEntryPoint {

    private final String applicationName;

    public DefaultAuthenticationEntryPoint(String loginFormUrl, String applicationName) {
        super(loginFormUrl);
        this.applicationName = applicationName;
    }

    @Override
    protected String determineUrlToUseForThisRequest(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) {
        String redirect = super.determineUrlToUseForThisRequest(request, response, exception);

        String continueParamValue = UrlUtils.buildFullRequestUrl(request);
        String continueUrl = Base64.getUrlEncoder().encodeToString(continueParamValue.getBytes(StandardCharsets.UTF_8));
        UriComponents continueUri = UriComponentsBuilder.fromHttpUrl(redirect)
                .queryParam("app", URLEncoder.encode(applicationName, StandardCharsets.UTF_8))
                .queryParam("continue", continueUrl)
                .build();

        return continueUri.toString();
    }
}

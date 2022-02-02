package ru.loolzaaa.sso.client.core.security;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class DefaultSsoClientAuthenticationEntryPoint extends LoginUrlAuthenticationEntryPoint {

    public DefaultSsoClientAuthenticationEntryPoint(String loginFormUrl) {
        super(loginFormUrl);
    }

    @Override
    protected String determineUrlToUseForThisRequest(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) {
        String redirect = super.determineUrlToUseForThisRequest(request, response, exception);

        String continueParamValue = UrlUtils.buildFullRequestUrl(request);
        byte[] bytes = Base64.getUrlEncoder().encode(continueParamValue.getBytes(StandardCharsets.UTF_8));
        UriComponents continueUri = UriComponentsBuilder.fromHttpUrl(redirect)
                .queryParam("continue", new String((bytes)))
                .build();

        return continueUri.toString();
    }
}

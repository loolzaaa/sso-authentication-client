package ru.loolzaaa.sso.client.core.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.UrlUtils;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class DefaultAuthenticationEntryPointTest {

    final String applicationName = "APP";
    final String loginFormUrl = "http://example.com/";

    @Mock
    HttpServletRequest request;
    @Mock
    HttpServletResponse response;
    @Mock
    AuthenticationException exception;

    DefaultAuthenticationEntryPoint authenticationEntryPoint;

    @BeforeEach
    void setUp() {
        authenticationEntryPoint = new DefaultAuthenticationEntryPoint(loginFormUrl, applicationName);
        when(request.getScheme()).thenReturn("http");
        when(request.getServerName()).thenReturn("example.com");
        when(request.getServerPort()).thenReturn(80);
        when(request.getRequestURI()).thenReturn("/test");
        when(request.getQueryString()).thenReturn(null);
    }

    @Test
    void shouldReturnContinueUrl() {
        String continueParamValue = UrlUtils.buildFullRequestUrl(request);
        byte[] bytes = Base64.getUrlEncoder().encode(continueParamValue.getBytes(StandardCharsets.UTF_8));

        String s = authenticationEntryPoint.determineUrlToUseForThisRequest(request, response, exception);

        assertThat(s)
                .isNotNull()
                .contains("continue=" + new String(bytes))
                .contains("app=" + applicationName);
    }

}
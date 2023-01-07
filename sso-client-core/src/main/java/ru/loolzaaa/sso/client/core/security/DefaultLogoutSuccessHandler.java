package ru.loolzaaa.sso.client.core.security;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;

import static java.lang.String.format;

public class DefaultLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {

    private final String entryPointAddress;

    private final RestTemplate restTemplate;

    public DefaultLogoutSuccessHandler(String entryPointAddress, RestTemplate restTemplate) {
        this.entryPointAddress = entryPointAddress;
        this.restTemplate = restTemplate;
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest req, HttpServletResponse resp, Authentication auth) throws IOException, ServletException {
        String accessToken = null;
        if (req.getCookies() != null) {
            Optional<String> token = Arrays.stream(req.getCookies())
                    .filter(cookie -> CookieName.ACCESS.getName().equals(cookie.getName()))
                    .map(Cookie::getValue)
                    .findFirst();
            accessToken = token.orElse(null);
        }

        if (accessToken != null) {
            HttpHeaders headers = new HttpHeaders();
            headers.add("Revoke-Token", accessToken);

            try {
                restTemplate.exchange(
                        entryPointAddress + "/api/fast/prepare_logout",
                        HttpMethod.POST,
                        new HttpEntity<>(headers),
                        Void.class
                );

                String acceptHeader = req.getHeader("Accept");
                if (acceptHeader != null && acceptHeader.toLowerCase().contains("application/json")) {
                    resp.sendRedirect(format("%s/api/logout?token=%s", entryPointAddress, accessToken));
                } else {
                    String continueParamValue = UrlUtils.buildFullRequestUrl(req).replace("/do_logout", "");
                    String encodedParam = Base64.getUrlEncoder().encodeToString(continueParamValue.getBytes(StandardCharsets.UTF_8));
                    UriComponents continueUri = UriComponentsBuilder.fromHttpUrl(entryPointAddress + "/api/logout")
                            .queryParam("token", accessToken)
                            .queryParam("continue", encodedParam)
                            .build();

                    resp.sendRedirect(continueUri.toString());
                }
            } catch (RestClientException e) {
                resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            }
        } else {
            super.onLogoutSuccess(req, resp, auth);
        }
    }
}

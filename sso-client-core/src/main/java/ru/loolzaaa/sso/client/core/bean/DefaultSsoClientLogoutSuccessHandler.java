package ru.loolzaaa.sso.client.core.bean;

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
import ru.loolzaaa.sso.client.core.UserService;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;

import static java.lang.String.*;

public class DefaultSsoClientLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {

    private final String entryPointAddress;

    private final String basicLogin;
    private final String basicPassword;

    private final UserService userService;

    private final RestTemplate restTemplate;

    public DefaultSsoClientLogoutSuccessHandler(String entryPointAddress, String basicLogin, String basicPassword,
                                                UserService userService, RestTemplate restTemplate) {
        this.entryPointAddress = entryPointAddress;
        this.basicLogin = basicLogin;
        this.basicPassword = basicPassword;
        this.userService = userService;
        this.restTemplate = restTemplate;
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest req, HttpServletResponse resp, Authentication auth) throws IOException, ServletException {
        String accessToken = null;
        if (req.getCookies() != null) {
            Optional<String> token = Arrays.stream(req.getCookies())
                    .filter(cookie -> "_t_access".equals(cookie.getName()))
                    .map(Cookie::getValue)
                    .findFirst();
            accessToken = token.orElse(null);
        }

        if (accessToken != null) {
            userService.removeUserFromApplicationByToken(accessToken);

            byte[] encodedBytes = Base64.getEncoder().encode(format("%s:%s", basicLogin, basicPassword).getBytes(StandardCharsets.US_ASCII));

            HttpHeaders headers = new HttpHeaders();
            headers.add(HttpHeaders.AUTHORIZATION, "Basic " + new String(encodedBytes));
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
                    resp.sendRedirect(format(entryPointAddress + "/api/logout?token=%s", accessToken));
                } else {
                    String continueParamValue = UrlUtils.buildFullRequestUrl(req).replace("/do_logout", "");
                    byte[] bytes = Base64.getUrlEncoder().encode(continueParamValue.getBytes(StandardCharsets.UTF_8));
                    UriComponents continueUri = UriComponentsBuilder.fromHttpUrl(entryPointAddress + "/api/logout")
                            .queryParam("token", accessToken)
                            .queryParam("continue", new String((bytes)))
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

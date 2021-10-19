package ru.loolzaaa.sso.client.core.bean;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.web.client.RestTemplate;
import ru.loolzaaa.sso.client.core.UserService;
import ru.loolzaaa.sso.client.core.model.UserPrincipal;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.StringJoiner;

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
        if (auth != null) {
            UserPrincipal userPrincipal = (UserPrincipal) auth.getPrincipal();
            userService.removeUserFromSystem(userPrincipal);
        } else {
            //TODO: log it
            //FIXME: find another way to delete user from system
        }

        byte[] encodedBytes = Base64.getEncoder().encode(format("%s:%s", basicLogin, basicPassword).getBytes(StandardCharsets.US_ASCII));

        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, "Basic " + new String(encodedBytes));

        StringJoiner cookieHeader = new StringJoiner("; ");
        if (req.getCookies() != null) {
            Arrays.stream(req.getCookies()).forEach(cookie -> {
                cookieHeader.add(cookie.getName() + "=" + cookie.getValue());
            });
            headers.add(HttpHeaders.COOKIE, cookieHeader.toString());
        }

        HttpEntity<Void> request = new HttpEntity<>(headers);

        ResponseEntity<Void> e = restTemplate.postForEntity(
                entryPointAddress + "/api/fast/logout",
                request,
                Void.class
        );

        List<String> resettableCookies = e.getHeaders().get("Set-Cookie");
        if (resettableCookies != null) {
           resettableCookies.forEach(cookie -> resp.addHeader(HttpHeaders.SET_COOKIE, cookie));
        }

        String acceptHeader = req.getHeader("Accept");
        if (acceptHeader != null && acceptHeader.toLowerCase().contains("application/json")) {
            resp.setStatus(HttpServletResponse.SC_OK);
        } else {
            super.onLogoutSuccess(req, resp, auth);
        }
    }
}

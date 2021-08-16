package ru.loolzaaa.authclientexample.config.security.bean;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import ru.loolzaaa.authclientexample.config.security.SecurityConfig;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.StringJoiner;

import static java.lang.String.format;

@Component
public class CustomLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {

    @Value("${auth.basic.login}")
    private String basicLogin;
    @Value("${auth.basic.password}")
    private String basicPassword;

    @Override
    public void onLogoutSuccess(HttpServletRequest req, HttpServletResponse resp, Authentication auth) throws IOException, ServletException {
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

        ResponseEntity<Void> e = new RestTemplate().postForEntity(
                SecurityConfig.ENTRY_POINT_ADDR + "/api/fast/logout",
                request,
                Void.class
        );

        List<String> resettableCookies = e.getHeaders().get("Set-Cookie");
        if (resettableCookies != null) {
           resettableCookies.forEach(cookie -> resp.addHeader(HttpHeaders.SET_COOKIE, cookie));
        }

        super.onLogoutSuccess(req, resp, auth);
    }
}

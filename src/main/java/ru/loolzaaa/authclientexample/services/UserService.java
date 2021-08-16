package ru.loolzaaa.authclientexample.services;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import ru.loolzaaa.authclientexample.config.security.SecurityConfig;
import ru.loolzaaa.authclientexample.model.UserPrincipal;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static java.lang.String.format;

@Service
public class UserService {

    @Value("${auth.application.name}")
    private String applicationName;
    @Value("${auth.basic.login}")
    private String basicLogin;
    @Value("${auth.basic.password}")
    private String basicPassword;

    private final RestTemplate restTemplate = new RestTemplate();

    public UserPrincipal getUserByUsername(String username) {
        byte[] encodedBytes = Base64.getEncoder().encode(format("%s:%s", basicLogin, basicPassword).getBytes(StandardCharsets.US_ASCII));

        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, "Basic " + new String(encodedBytes));

        HttpEntity<Void> request = new HttpEntity<>(headers);

        ResponseEntity<UserPrincipal> userEntity = restTemplate.exchange(
                SecurityConfig.ENTRY_POINT_ADDR + "/api/fast/user/get/{username}?app={app}",
                HttpMethod.GET,
                request,
                UserPrincipal.class,
                username,
                applicationName
        );

        if (userEntity.getBody() == null) {
            throw new UsernameNotFoundException(String.format("User with login=%s not found", username));
        } else {
            return userEntity.getBody();
        }
    }
}

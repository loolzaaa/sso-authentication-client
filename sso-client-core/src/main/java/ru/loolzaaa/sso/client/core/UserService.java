package ru.loolzaaa.sso.client.core;

import com.fasterxml.jackson.databind.JsonNode;
import io.jsonwebtoken.ClaimJwtException;
import io.jsonwebtoken.Claims;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.client.RestTemplate;
import ru.loolzaaa.sso.client.core.context.UserStore;
import ru.loolzaaa.sso.client.core.model.User;
import ru.loolzaaa.sso.client.core.model.UserPrincipal;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

import static java.lang.String.*;

public class UserService {

    private final String applicationName;

    private final String entryPointAddress;

    private final String basicLogin;
    private final String basicPassword;

    private final RestTemplate restTemplate;

    private final UserStore userStore;

    private final JWTUtils jwtUtils;

    public UserService(String applicationName, String entryPointAddress, String basicLogin,
                       String basicPassword, RestTemplate restTemplate, UserStore userStore, JWTUtils jwtUtils) {
        this.applicationName = applicationName;
        this.entryPointAddress = entryPointAddress;
        this.basicLogin = basicLogin;
        this.basicPassword = basicPassword;
        this.restTemplate = restTemplate;
        this.userStore = userStore;
        this.jwtUtils = jwtUtils;
    }

    public UserPrincipal getUserFromServerByUsername(String username) {
        byte[] encodedBytes = Base64.getEncoder().encode(format("%s:%s", basicLogin, basicPassword).getBytes(StandardCharsets.US_ASCII));

        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, "Basic " + new String(encodedBytes));

        HttpEntity<Void> request = new HttpEntity<>(headers);

        ResponseEntity<UserPrincipal> userEntity = restTemplate.exchange(
                entryPointAddress + "/api/fast/user/get/{username}?app={app}",
                HttpMethod.GET,
                request,
                UserPrincipal.class,
                username,
                applicationName
        );

        UserPrincipal body = userEntity.getBody();
        if (body == null) {
            throw new UsernameNotFoundException(String.format("User with login=%s not found", username));
        } else {
            return body;
        }
    }

    public UserPrincipal[] getUsersFromServerByAuthority(String authority) {
        byte[] encodedBytes = Base64.getEncoder().encode(format("%s:%s", basicLogin, basicPassword).getBytes(StandardCharsets.US_ASCII));

        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, "Basic " + new String(encodedBytes));

        HttpEntity<Void> request = new HttpEntity<>(headers);

        ResponseEntity<UserPrincipal[]> userEntity = restTemplate.exchange(
                entryPointAddress + "/api/fast/users?app={app}&authority={authority}",
                HttpMethod.GET,
                request,
                UserPrincipal[].class,
                applicationName,
                authority
        );

        if (userEntity.getBody() == null) {
            throw new UsernameNotFoundException(String.format("Users with authority=%s not found", authority));
        } else {
            return userEntity.getBody();
        }
    }

    public int updateUserConfigOnServer(String username, String app, JsonNode config) {
        byte[] encodedBytes = Base64.getEncoder().encode(format("%s:%s", basicLogin, basicPassword).getBytes(StandardCharsets.US_ASCII));

        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, "Basic " + new String(encodedBytes));

        HttpEntity<JsonNode> request = new HttpEntity<>(config, headers);

        restTemplate.exchange(
                entryPointAddress + "/api/fast/user/{username}/config/{app}",
                HttpMethod.PATCH,
                request,
                Void.class,
                username,
                app
        );
        return 0;
    }

    public void saveRequestUser(UserPrincipal user) {
        User newUser = user.getUser();

        if (newUser == null) {
            throw new NoSuchElementException("Can't find user");
        }

        List<String> authorities = user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(authority -> !applicationName.equals(authority))
                .collect(Collectors.toList());

        newUser.setAuthorities(authorities);
        userStore.saveRequestUser(newUser);
    }

    public void clearRequestUser() {
        userStore.clearRequestUser();
    }

    public User getRequestUser() {
        return userStore.getRequestUser();
    }

    public String getApplicationName() {
        return applicationName;
    }

    public Map<String, String> getTokenClaims(String token) {
        Map<String, String> stringClaims = new HashMap<>();

        if (token == null) throw new NullPointerException("Token must be not null");

        Claims claims;
        try {
            claims = jwtUtils.parserEnforceAccessToken(token).getBody();
        } catch (ClaimJwtException e) {
            claims = e.getClaims();
        }
        claims.forEach((s, o) -> stringClaims.put(s, (String) o));

        return stringClaims;
    }
}

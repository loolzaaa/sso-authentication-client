package ru.loolzaaa.sso.client.core;

import com.fasterxml.jackson.databind.JsonNode;
import io.jsonwebtoken.ClaimJwtException;
import io.jsonwebtoken.Claims;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import ru.loolzaaa.sso.client.core.context.UserStore;
import ru.loolzaaa.sso.client.core.model.User;
import ru.loolzaaa.sso.client.core.model.UserPrincipal;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.stream.Collectors;

public class UserService {

    private final String applicationName;

    private final String entryPointAddress;

    private final RestTemplate restTemplate;

    private final UserStore userStore;

    private final JWTUtils jwtUtils;

    private final boolean tokenApiUse;

    public UserService(String applicationName, String entryPointAddress, RestTemplate restTemplate,
                       UserStore userStore, JWTUtils jwtUtils, boolean tokenApiUse) {
        this.applicationName = applicationName;
        this.entryPointAddress = entryPointAddress;
        this.restTemplate = restTemplate;
        this.userStore = userStore;
        this.jwtUtils = jwtUtils;
        this.tokenApiUse = tokenApiUse;
    }

    public UserPrincipal getUserFromServerByUsername(String username) {
        final String API_URI = tokenApiUse ? "/api/user/{username}?app={app}" : "/api/fast/user/{username}?app={app}";
        UserPrincipal userPrincipal;
        try {
            ResponseEntity<UserPrincipal> userEntity = restTemplate.getForEntity(
                    entryPointAddress + API_URI,
                    UserPrincipal.class,
                    username,
                    applicationName);
            userPrincipal = userEntity.getBody();
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode().equals(HttpStatus.BAD_REQUEST)) {
                throw new UsernameNotFoundException(String.format("User with login=%s not found", username));
            } else {
                throw e;
            }
        }
        return userPrincipal;
    }

    public UserPrincipal[] getUsersFromServerByAuthority(String authority) {
        final String API_URI = tokenApiUse ? "/api/users?app={app}&authority={authority}" : "/api/fast/users?app={app}&authority={authority}";
        UserPrincipal[] users;
        try {
            ResponseEntity<UserPrincipal[]> userEntity = restTemplate.getForEntity(
                    entryPointAddress + API_URI,
                    UserPrincipal[].class,
                    applicationName,
                    authority);
            users = userEntity.getBody();
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode().equals(HttpStatus.BAD_REQUEST)) {
                throw new UsernameNotFoundException(String.format("Users with authority=%s not found", authority));
            } else {
                throw e;
            }
        }
        return users;
    }

    public int updateUserConfigOnServer(String username, String app, JsonNode config) {
        final String API_URI = tokenApiUse ? "/api/user/{username}/config/{app}" : "/api/fast/user/{username}/config/{app}";
        HttpEntity<JsonNode> request = new HttpEntity<>(config);
        try {
            restTemplate.exchange(
                    entryPointAddress + API_URI,
                    HttpMethod.PATCH,
                    request,
                    Void.class,
                    username,
                    app);
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode().equals(HttpStatus.BAD_REQUEST)) {
                return -1;
            } else {
                return -2;
            }
        } catch (Exception e) {
            return -2;
        }
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

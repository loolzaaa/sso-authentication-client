package ru.loolzaaa.sso.client.core.context;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.ClaimJwtException;
import io.jsonwebtoken.Claims;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import ru.loolzaaa.sso.client.core.dto.CreateUserRequestDTO;
import ru.loolzaaa.sso.client.core.dto.RequestStatusDTO;
import ru.loolzaaa.sso.client.core.model.BaseUserConfig;
import ru.loolzaaa.sso.client.core.model.User;
import ru.loolzaaa.sso.client.core.model.UserPrincipal;
import ru.loolzaaa.sso.client.core.util.JWTUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class UserService {

    private final String applicationName;

    private final String entryPointAddress;

    private final RestTemplate restTemplate;

    private final UserStore userStore;

    private final JWTUtils jwtUtils;

    private final boolean tokenApiUse;

    private final ObjectMapper mapper = new ObjectMapper();

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
        UserPrincipal userPrincipal = null;
        try {
            ResponseEntity<UserPrincipal> userEntity = restTemplate.getForEntity(
                    entryPointAddress + API_URI,
                    UserPrincipal.class,
                    username,
                    applicationName);
            userPrincipal = userEntity.getBody();
        } catch (Exception e) {
            handleSecurityException(e);
        }
        if (userPrincipal == null) {
            throw new NullPointerException("User principal null");
        }
        postProcessUserPrincipal(userPrincipal);
        return userPrincipal;
    }

    public List<UserPrincipal> getUsersFromServerByAuthority(String authority) {
        final String API_URI = tokenApiUse ? "/api/users?app={app}&authority={authority}" : "/api/fast/users?app={app}&authority={authority}";
        UserPrincipal[] userPrincipalArray = null;
        try {
            ResponseEntity<UserPrincipal[]> userEntity = restTemplate.getForEntity(
                    entryPointAddress + API_URI,
                    UserPrincipal[].class,
                    applicationName,
                    authority);
            userPrincipalArray = userEntity.getBody();
        } catch (Exception e) {
            handleSecurityException(e);
        }
        if (userPrincipalArray == null) {
            throw new NullPointerException("User principals null");
        }
        List<UserPrincipal> userPrincipals = new ArrayList<>(userPrincipalArray.length);
        for (UserPrincipal userPrincipal : userPrincipalArray) {
            postProcessUserPrincipal(userPrincipal);
            userPrincipals.add(userPrincipal);
        }
        return userPrincipals;
    }

    public RequestStatusDTO updateUserConfigOnServer(String username, BaseUserConfig config) {
        final String API_URI = tokenApiUse ? "/api/user/{username}/config/{app}" : "/api/fast/user/{username}/config/{app}";
        HttpEntity<BaseUserConfig> request = new HttpEntity<>(config);
        RequestStatusDTO requestStatus = null;
        try {
            ResponseEntity<RequestStatusDTO> response = restTemplate.exchange(
                    entryPointAddress + API_URI,
                    HttpMethod.PATCH,
                    request,
                    RequestStatusDTO.class,
                    username,
                    applicationName);
            requestStatus = response.getBody();
        } catch (Exception e) {
            handleSecurityException(e);
        }
        if (requestStatus == null) {
            return new RequestStatusDTO("ERROR", "Response body is null");
        }
        return requestStatus;
    }

    public RequestStatusDTO deleteUserConfigOnServer(String username) {
        if (!tokenApiUse) {
            return new RequestStatusDTO("ERROR", "SSO Client without tokens cannot delete configs");
        }
        final String API_URI = "/api/user/{username}/config/{app}";
        RequestStatusDTO requestStatus = null;
        try {
            ResponseEntity<RequestStatusDTO> response = restTemplate.exchange(
                    entryPointAddress + API_URI,
                    HttpMethod.DELETE,
                    null,
                    RequestStatusDTO.class,
                    username,
                    applicationName);
            requestStatus = response.getBody();
        } catch (Exception e) {
            handleSecurityException(e);
        }
        if (requestStatus == null) {
            return new RequestStatusDTO("ERROR", "Response body is null");
        }
        return requestStatus;
    }

    public RequestStatusDTO createUserConfigOnServer(String username, String name, BaseUserConfig config) {
        if (!tokenApiUse) {
            return new RequestStatusDTO("ERROR", "SSO Client without tokens cannot create configs");
        }
        final String API_URI = "/api/user?app=" + applicationName;
        CreateUserRequestDTO requestDTO = new CreateUserRequestDTO(username, name, config);
        HttpEntity<CreateUserRequestDTO> request = new HttpEntity<>(requestDTO);
        RequestStatusDTO requestStatus = null;
        try {
            ResponseEntity<RequestStatusDTO> response = restTemplate.exchange(entryPointAddress + API_URI,
                    HttpMethod.PUT,
                    request,
                    RequestStatusDTO.class);
            requestStatus = response.getBody();
        } catch (Exception e) {
            handleSecurityException(e);
        }
        if (requestStatus == null) {
            return new RequestStatusDTO("ERROR", "Response body is null");
        }
        return requestStatus;
    }

    public void saveRequestUser(UserPrincipal userPrincipal) {
        User user = userPrincipal.getUser();
        if (user == null) {
            throw new NullPointerException("Can't find user");
        }
        userStore.saveRequestUser(user);
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
        claims.forEach((s, o) -> stringClaims.put(s, o.toString()));

        return stringClaims;
    }

    private void postProcessUserPrincipal(UserPrincipal userPrincipal) {
        List<String> authorities = userPrincipal.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(authority -> !applicationName.equals(authority))
                .collect(Collectors.toList());
        BaseUserConfig config = userPrincipal.getUser().getConfig();
        if (config.getRoles() == null) {
            config.setRoles(new ArrayList<>(4));
        }
        if (config.getPrivileges() == null) {
            config.setPrivileges(new ArrayList<>(4));
        }
        for (String authority : authorities) {
            if (authority.startsWith("ROLE_")) {
                config.getRoles().add(authority);
            } else {
                config.getPrivileges().add(authority);
            }
        }
    }

    private void handleSecurityException(Exception e) {
        if (e instanceof HttpClientErrorException) {
            HttpClientErrorException clientError = (HttpClientErrorException) e;
            if (clientError.getStatusCode().equals(HttpStatus.BAD_REQUEST)) {
                JsonNode errorResponse;
                try {
                    errorResponse = mapper.readTree(clientError.getResponseBodyAsByteArray());
                } catch (Exception ex) {
                    throw new AccessDeniedException(e.getMessage());
                }
                if (errorResponse.has("text")) {
                    throw new AccessDeniedException(errorResponse.get("text").asText());
                } else {
                    throw new AccessDeniedException(e.getMessage());
                }
            } else {
                throw clientError;
            }
        } else {
            throw new RuntimeException(e);
        }
    }
}

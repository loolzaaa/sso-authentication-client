package ru.loolzaaa.sso.client.core.endpoint.service;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import ru.loolzaaa.sso.client.core.UserService;
import ru.loolzaaa.sso.client.core.model.User;
import ru.loolzaaa.sso.client.core.model.UserPrincipal;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class SsoClientServiceImpl implements SsoClientService {

    private final UserService userService;

    public SsoClientServiceImpl(UserService userService) {
        this.userService = userService;
    }

    @Override
    public String getApplicationName() {
        return String.format("{\"app\":\"%s\"}", userService.getApplicationName());
    }

    @Override
    public List<User> getUsersForApplicationFromServer() {
        UserPrincipal[] usersPrincipals = userService.getUsersFromServerByAuthority(userService.getApplicationName());

        List<User> users = Arrays.stream(usersPrincipals)
                .map(UserPrincipal::getUser)
                .collect(Collectors.toList());

        Map<String, List<String>> userAuthorities = new HashMap<>();

        Arrays.stream(usersPrincipals).forEach(userPrincipal -> {
            String username = userPrincipal.getUsername();
            List<String> authorities = userPrincipal.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());
            userAuthorities.put(username, authorities);
        });

        users.forEach(user -> user.setAuthorities(userAuthorities.get(user.getLogin())));

        return users;
    }

    @Override
    public int updateUserConfigOnServer(String username, String app, JsonNode config) {
        // Remove privilege with application name
        JsonNode privilegesNode = config.get("privileges");
        if (privilegesNode != null) {
            Iterator<JsonNode> it = privilegesNode.elements();
            while (it.hasNext()) {
                JsonNode privilege = it.next();
                if (privilege.isTextual() && userService.getApplicationName().equals(privilege.asText())) {
                    it.remove();
                    break;
                }
            }
        } else {
            return 1;
        }
        return userService.updateUserConfigOnServer(username, app, config);
    }
}

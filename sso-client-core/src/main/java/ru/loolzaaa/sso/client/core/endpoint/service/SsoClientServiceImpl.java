package ru.loolzaaa.sso.client.core.endpoint.service;

import org.springframework.stereotype.Service;
import ru.loolzaaa.sso.client.core.context.UserService;
import ru.loolzaaa.sso.client.core.model.BaseUserConfig;
import ru.loolzaaa.sso.client.core.model.User;
import ru.loolzaaa.sso.client.core.model.UserPrincipal;

import java.util.List;
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
        List<UserPrincipal> usersPrincipals = userService.getUsersFromServerByAuthority(userService.getApplicationName());
        return usersPrincipals.stream()
                .map(UserPrincipal::getUser)
                .collect(Collectors.toList());
    }

    @Override
    public int updateUserConfigOnServer(String username, String app, BaseUserConfig config) {
        return userService.updateUserConfigOnServer(username, app, config);
    }
}

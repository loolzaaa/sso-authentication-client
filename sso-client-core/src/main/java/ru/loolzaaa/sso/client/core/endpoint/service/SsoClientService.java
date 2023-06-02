package ru.loolzaaa.sso.client.core.endpoint.service;

import ru.loolzaaa.sso.client.core.dto.RequestStatusDTO;
import ru.loolzaaa.sso.client.core.model.BaseUserConfig;
import ru.loolzaaa.sso.client.core.model.User;

import java.util.List;

public interface SsoClientService {
    String getApplicationName();
    List<User> getUsersForApplicationFromServer();
    RequestStatusDTO updateUserConfigOnServer(String username, BaseUserConfig config);
    RequestStatusDTO deleteUserConfigOnServer(String username);
    RequestStatusDTO createUserConfigOnServer(String username, String name, BaseUserConfig config);
}

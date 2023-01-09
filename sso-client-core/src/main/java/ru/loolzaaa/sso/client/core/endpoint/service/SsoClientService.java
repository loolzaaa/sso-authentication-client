package ru.loolzaaa.sso.client.core.endpoint.service;

import ru.loolzaaa.sso.client.core.model.BaseUserConfig;
import ru.loolzaaa.sso.client.core.model.User;

import java.util.List;

public interface SsoClientService {
    String getApplicationName();
    List<User> getUsersForApplicationFromServer();
    int updateUserConfigOnServer(String username, String app, BaseUserConfig config);
}

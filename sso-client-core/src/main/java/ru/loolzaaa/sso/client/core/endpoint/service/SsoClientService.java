package ru.loolzaaa.sso.client.core.endpoint.service;

import com.fasterxml.jackson.databind.JsonNode;
import ru.loolzaaa.sso.client.core.model.User;

import java.util.List;

public interface SsoClientService {
    String getApplicationName();
    List<User> getUsersForApplicationFromServer();
    int updateUserConfigOnServer(String username, String app, JsonNode config);
}

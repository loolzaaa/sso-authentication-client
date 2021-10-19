package ru.loolzaaa.sso.client.core.context;

import ru.loolzaaa.sso.client.core.model.User;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class UserStore {
    private Map<String, User> users = new ConcurrentHashMap<>();

    public Map<String, User> getUsers() {
        return users;
    }
}

package ru.loolzaaa.sso.client.core.context;

import ru.loolzaaa.sso.client.core.model.User;

public class UserStore {

    private final ThreadLocal<User> requestUser = new ThreadLocal<>();

    public User getRequestUser() {
        return requestUser.get();
    }

    public void saveRequestUser(User user) {
        requestUser.set(user);
    }

    public void clearRequestUser() {
        requestUser.remove();
    }
}

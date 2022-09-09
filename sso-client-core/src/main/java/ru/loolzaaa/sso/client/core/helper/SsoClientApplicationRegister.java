package ru.loolzaaa.sso.client.core.helper;

import ru.loolzaaa.sso.client.core.model.UserPrincipal;

public interface SsoClientApplicationRegister {
    default void register(UserPrincipal userPrincipal) {
    }
}

package ru.loolzaaa.sso.client.core.security;

public enum CookieName {
    ACCESS("_t_access"),
    REFRESH("_t_refresh"),
    RFID("_t_rfid");

    private final String name;

    CookieName(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }
}

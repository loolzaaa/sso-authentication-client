package ru.loolzaaa.sso.client.core.model;

import org.springframework.security.core.GrantedAuthority;

public class UserGrantedAuthority implements GrantedAuthority {

    private String authority;

    public UserGrantedAuthority() {
    }

    public UserGrantedAuthority(String authority) {
        this.authority = authority;
    }

    public void setAuthority(String authority) {
        this.authority = authority;
    }

    public String getAuthority() {
        return authority;
    }
}

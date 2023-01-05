package ru.loolzaaa.sso.client.core.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

import java.util.Objects;

public class UserGrantedAuthority implements GrantedAuthority {

    private String authority;

    @JsonCreator
    public UserGrantedAuthority(@JsonProperty("authority") String authority) {
        Assert.hasText(authority, "A granted authority textual representation is required");
        this.authority = authority;
    }

    public void setAuthority(String authority) {
        this.authority = authority;
    }

    @Override
    public String getAuthority() {
        return authority;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserGrantedAuthority that = (UserGrantedAuthority) o;
        return authority.equals(that.authority);
    }

    @Override
    public int hashCode() {
        return Objects.hash(authority);
    }
}

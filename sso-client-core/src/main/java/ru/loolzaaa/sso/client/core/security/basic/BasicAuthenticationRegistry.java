package ru.loolzaaa.sso.client.core.security.basic;

import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import ru.loolzaaa.sso.client.core.model.UserGrantedAuthority;

import java.util.Map;
import java.util.Objects;
import java.util.Set;

public class BasicAuthenticationRegistry {

    private final Set<User> users;
    private final Map<AntPathRequestMatcher, String[]> requestMatcherAuthoritiesMap;

    public BasicAuthenticationRegistry(Set<User> users, Map<AntPathRequestMatcher,
            String[]> requestMatcherAuthoritiesMap) {
        this.users = users;
        this.requestMatcherAuthoritiesMap = requestMatcherAuthoritiesMap;
    }

    public Set<User> getUsers() {
        return users;
    }

    public Map<AntPathRequestMatcher, String[]> getRequestMatcherAuthoritiesMap() {
        return requestMatcherAuthoritiesMap;
    }

    public static class User {
        private final String username;
        private final String password;
        private final Set<UserGrantedAuthority> authorities;

        public User(String username, String password, Set<UserGrantedAuthority> authorities) {
            this.username = username;
            this.password = password;
            this.authorities = authorities;
        }

        public String getUsername() {
            return username;
        }

        public String getPassword() {
            return password;
        }

        public Set<UserGrantedAuthority> getAuthorities() {
            return authorities;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            User user = (User) o;
            return username.equals(user.username);
        }

        @Override
        public int hashCode() {
            return Objects.hash(username);
        }
    }
}

package ru.loolzaaa.sso.client.autoconfigure;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties("sso.client.basic")
public class BasicAuthenticationProperties {

    private boolean enable = false;
    private String realmName = "Basic realm";
    private final List<User> users = new ArrayList<>();
    private final List<Matcher> requestMatchers = new ArrayList<>();

    public boolean isEnable() {
        return enable;
    }

    public void setEnable(boolean enable) {
        this.enable = enable;
    }

    public String getRealmName() {
        return realmName;
    }

    public void setRealmName(String realmName) {
        this.realmName = realmName;
    }

    public List<User> getUsers() {
        return users;
    }

    public List<Matcher> getRequestMatchers() {
        return requestMatchers;
    }

    public static class User {
        private String username;
        private String password;
        private List<String> authorities;

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public List<String> getAuthorities() {
            return authorities;
        }

        public void setAuthorities(List<String> authorities) {
            this.authorities = authorities;
        }
    }

    public static class Matcher {
        private String pattern;
        private String httpMethod;
        private Boolean caseSensitive;
        private List<String> authorities;

        public String getPattern() {
            return pattern;
        }

        public void setPattern(String pattern) {
            this.pattern = pattern;
        }

        public String getHttpMethod() {
            return httpMethod;
        }

        public void setHttpMethod(String httpMethod) {
            this.httpMethod = httpMethod;
        }

        public Boolean getCaseSensitive() {
            return caseSensitive;
        }

        public void setCaseSensitive(Boolean caseSensitive) {
            this.caseSensitive = caseSensitive;
        }

        public List<String> getAuthorities() {
            return authorities;
        }

        public void setAuthorities(List<String> authorities) {
            this.authorities = authorities;
        }

        @Override
        public String toString() {
            return "Matcher{" +
                    "pattern='" + pattern + '\'' +
                    ", httpMethod='" + httpMethod + '\'' +
                    '}';
        }
    }
}

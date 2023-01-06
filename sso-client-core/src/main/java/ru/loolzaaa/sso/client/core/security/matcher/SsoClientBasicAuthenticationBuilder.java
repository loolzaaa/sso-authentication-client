package ru.loolzaaa.sso.client.core.security.matcher;

import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;
import ru.loolzaaa.sso.client.core.model.UserGrantedAuthority;

import java.util.*;
import java.util.stream.Collectors;

public class SsoClientBasicAuthenticationBuilder {

    private final Set<SsoClientBasicAuthenticationRegistry.User> users = new HashSet<>();
    private final Map<AntPathRequestMatcher, String[]> requestMatcherAuthoritiesMap = new HashMap<>();

    public SsoClientBasicAuthenticationBuilder addUser(String username, String password, Collection<String> authorities) {
        Set<UserGrantedAuthority> userGrantedAuthorities = authorities.stream()
                .map(UserGrantedAuthority::new)
                .collect(Collectors.toSet());
        SsoClientBasicAuthenticationRegistry.User user =
                new SsoClientBasicAuthenticationRegistry.User(username, password, userGrantedAuthorities);
        users.add(user);
        return this;
    }

    public SsoClientBasicAuthenticationBuilder addRequestMatcher(String pattern, String... authorities) {
        return addRequestMatcher(pattern, "GET", authorities);
    }

    public SsoClientBasicAuthenticationBuilder addRequestMatcher(String pattern, String httpMethod, String... authorities) {
        return addRequestMatcher(pattern, httpMethod, false, authorities);
    }

    public SsoClientBasicAuthenticationBuilder addRequestMatcher(String pattern, String httpMethod, boolean caseSensitive, String... authorities) {
        Assert.notEmpty(authorities, "At least one authority needs for request matcher");
        //TODO: pattern cannot starts with /sso and permit all matchers
        AntPathRequestMatcher requestMatcher = new AntPathRequestMatcher(pattern, httpMethod, caseSensitive);
        requestMatcherAuthoritiesMap.put(requestMatcher, authorities);
        return this;
    }

    public SsoClientBasicAuthenticationRegistry build() {
        return new SsoClientBasicAuthenticationRegistry(users, requestMatcherAuthoritiesMap);
    }
}

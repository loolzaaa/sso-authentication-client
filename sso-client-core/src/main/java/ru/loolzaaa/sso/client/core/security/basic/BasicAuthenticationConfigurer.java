package ru.loolzaaa.sso.client.core.security.basic;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;
import ru.loolzaaa.sso.client.core.model.UserGrantedAuthority;

import java.util.*;
import java.util.stream.Collectors;

public class BasicAuthenticationConfigurer {

    private static final Logger log = LogManager.getLogger(BasicAuthenticationConfigurer.class);

    private final Set<BasicAuthenticationRegistry.User> users = new HashSet<>();
    private final Map<AntPathRequestMatcher, String[]> requestMatcherAuthoritiesMap = new HashMap<>();

    public BasicAuthenticationConfigurer addUser(String username, String password, Collection<String> authorities) {
        Set<UserGrantedAuthority> userGrantedAuthorities = authorities.stream()
                .map(UserGrantedAuthority::new)
                .collect(Collectors.toSet());
        BasicAuthenticationRegistry.User user =
                new BasicAuthenticationRegistry.User(username, password, userGrantedAuthorities);
        users.add(user);
        log.debug("Add basic user: {}", username);
        return this;
    }

    public BasicAuthenticationConfigurer addRequestMatcher(String pattern, String... authorities) {
        return addRequestMatcher(pattern, "GET", authorities);
    }

    public BasicAuthenticationConfigurer addRequestMatcher(String pattern, String httpMethod, String... authorities) {
        return addRequestMatcher(pattern, httpMethod, false, authorities);
    }

    public BasicAuthenticationConfigurer addRequestMatcher(String pattern, String httpMethod, boolean caseSensitive, String... authorities) {
        Assert.notEmpty(authorities, "At least one authority needs for request matcher");
        AntPathRequestMatcher requestMatcher = new AntPathRequestMatcher(pattern, httpMethod, caseSensitive);
        requestMatcherAuthoritiesMap.put(requestMatcher, authorities);
        log.debug("Add basic request matcher: {} {}. Allowed authorities: {}", httpMethod, pattern, authorities);
        return this;
    }

    public BasicAuthenticationRegistry buildRegistry() {
        return new BasicAuthenticationRegistry(users, requestMatcherAuthoritiesMap);
    }
}

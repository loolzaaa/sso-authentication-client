package ru.loolzaaa.sso.client.core.security.matcher;

import org.springframework.http.HttpMethod;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.HashSet;
import java.util.Set;

public class PermitAllMatcherRegistry {

    private final Set<PermitAllMatcher> matchers = new HashSet<>();

    public void addPermitAllMatcher(HttpMethod method, boolean ignoreCsrf, String... antPatterns) {
        for (String pattern : antPatterns) {
            AntPathRequestMatcher antPathRequestMatcher = new AntPathRequestMatcher(pattern, method.toString());
            matchers.add(new PermitAllMatcher(antPathRequestMatcher, ignoreCsrf));
        }
    }

    public void addPermitAllMatcher(boolean ignoreCsrf, String... antPatterns) {
        addPermitAllMatcher(null, ignoreCsrf, antPatterns);
    }

    public void addPermitAllMatcher(String... antPatterns) {
        addPermitAllMatcher(null, false, antPatterns);
    }

    public Set<PermitAllMatcher> getMatchers() {
        return matchers;
    }
}

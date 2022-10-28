package ru.loolzaaa.sso.client.core.helper;

import org.springframework.http.HttpMethod;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.HashSet;
import java.util.Set;

public class SsoClientPermitAllMatcherHandler {

    private final Set<SsoClientPermitAllMatcher> matchers = new HashSet<>();

    public void addPermitAllMatcher(HttpMethod method, boolean ignoreCsrf, String... antPatterns) {
        for (String pattern : antPatterns) {
            AntPathRequestMatcher antPathRequestMatcher = new AntPathRequestMatcher(pattern, method.toString());
            matchers.add(new SsoClientPermitAllMatcher(antPathRequestMatcher, ignoreCsrf));
        }
    }

    public void addPermitAllMatcher(boolean ignoreCsrf, String... antPatterns) {
        addPermitAllMatcher(null, ignoreCsrf, antPatterns);
    }

    public void addPermitAllMatcher(String... antPatterns) {
        addPermitAllMatcher(null, false, antPatterns);
    }

    public Set<SsoClientPermitAllMatcher> getMatchers() {
        return matchers;
    }
}

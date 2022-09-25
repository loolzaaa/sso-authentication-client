package ru.loolzaaa.sso.client.core.helper;

import org.springframework.http.HttpMethod;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.ArrayList;
import java.util.List;

public class SsoClientPermitAllMatcherHandler {

    private final List<AntPathRequestMatcher> matchers = new ArrayList<>();

    public void addPermitAllMatcher(HttpMethod method, String... antPatterns) {
        for (String pattern : antPatterns) {
            matchers.add(new AntPathRequestMatcher(pattern, method.toString()));
        }
    }

    public void addPermitAllMatcher(String... antPatterns) {
        addPermitAllMatcher(null, antPatterns);
    }

    public List<AntPathRequestMatcher> getMatchers() {
        return matchers;
    }
}

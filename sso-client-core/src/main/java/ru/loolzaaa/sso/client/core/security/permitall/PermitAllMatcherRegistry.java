package ru.loolzaaa.sso.client.core.security.permitall;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.HashSet;
import java.util.Set;

public class PermitAllMatcherRegistry {

    private static final Logger log = LogManager.getLogger(PermitAllMatcherRegistry.class);

    private final Set<PermitAllMatcher> matchers = new HashSet<>();

    public void addPermitAllMatcher(PermitAllMatcher matcher) {
        matchers.add(matcher);
        log.info("Add permit all matcher: {}", matcher);
    }

    public void addPermitAllMatcher(HttpMethod method, boolean ignoreCsrf, String... antPatterns) {
        for (String pattern : antPatterns) {
            AntPathRequestMatcher antPathRequestMatcher;
            if (method == null) {
                antPathRequestMatcher = new AntPathRequestMatcher(pattern);
            } else {
                antPathRequestMatcher = new AntPathRequestMatcher(pattern, method.toString());
            }
            PermitAllMatcher matcher = new PermitAllMatcher(antPathRequestMatcher, ignoreCsrf);
            addPermitAllMatcher(matcher);
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

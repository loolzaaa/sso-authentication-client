package ru.loolzaaa.sso.client.core.security.matcher;

import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.Objects;

public final class SsoClientPermitAllMatcher {

    private final AntPathRequestMatcher requestMatcher;
    private final boolean ignoreCsrf;

    public SsoClientPermitAllMatcher(AntPathRequestMatcher requestMatcher, boolean ignoreCsrf) {
        this.requestMatcher = requestMatcher;
        this.ignoreCsrf = ignoreCsrf;
    }

    public AntPathRequestMatcher getRequestMatcher() {
        return requestMatcher;
    }

    public boolean isIgnoreCsrf() {
        return ignoreCsrf;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SsoClientPermitAllMatcher that = (SsoClientPermitAllMatcher) o;
        return getRequestMatcher().equals(that.getRequestMatcher());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getRequestMatcher());
    }

    @Override
    public String toString() {
        return "SsoClientPermitAllMatcher{" +
                "requestMatcher=" + requestMatcher +
                ", ignoreCsrf=" + ignoreCsrf +
                '}';
    }
}

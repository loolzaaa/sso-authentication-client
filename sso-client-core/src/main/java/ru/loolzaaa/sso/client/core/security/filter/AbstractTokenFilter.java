package ru.loolzaaa.sso.client.core.security.filter;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;
import ru.loolzaaa.sso.client.core.application.SsoClientApplicationRegister;
import ru.loolzaaa.sso.client.core.context.UserService;
import ru.loolzaaa.sso.client.core.model.User;
import ru.loolzaaa.sso.client.core.model.UserGrantedAuthority;
import ru.loolzaaa.sso.client.core.model.UserPrincipal;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

public abstract class AbstractTokenFilter<T> extends OncePerRequestFilter {

    private final UserService userService;

    private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

    private final List<SsoClientApplicationRegister> ssoClientApplicationRegisters = new ArrayList<>();

    private final String anonymousKey = UUID.randomUUID().toString();
    private final List<GrantedAuthority> anonymousAuthorities = AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS");
    private AuthorizationManager<HttpServletRequest> permitAllAuthorizationManager;

    public AbstractTokenFilter(UserService userService) {
        this.userService = userService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse resp,
                                    FilterChain chain) throws ServletException, IOException {
        if (isPermitAllRequest(req)) {
            logger.debug("Permit access to: " + req.getRequestURL().toString());
            chain.doFilter(req, resp);
            return;
        }

        T tokenData;
        try {
            tokenData = extractTokenData(req, resp);
        } catch (IllegalArgumentException e) {
            logger.trace(e.getMessage());
            chain.doFilter(req, resp);
            return;
        }

        if (tokenData != null) {
            UserPrincipal userPrincipal = authenticateUser(req, tokenData);

            userService.saveRequestUser(userPrincipal);

            try {
                for (SsoClientApplicationRegister applicationRegister : ssoClientApplicationRegisters) {
                    applicationRegister.register(userPrincipal);
                }
                chain.doFilter(req, resp);
            } finally {
                userService.clearRequestUser();
            }
        } else {
            handleInvalidTokenData(req, resp, chain);
        }
    }

    protected abstract T extractTokenData(HttpServletRequest req, HttpServletResponse resp) throws IOException;

    protected abstract UserData processTokenData(HttpServletRequest req, T tokenData);

    protected abstract void handleInvalidTokenData(HttpServletRequest req, HttpServletResponse resp,
                                                   FilterChain chain) throws IOException;

    public void addApplicationRegisters(List<SsoClientApplicationRegister> applicationRegisters) {
        if (applicationRegisters != null && !applicationRegisters.isEmpty()) {
            ssoClientApplicationRegisters.addAll(applicationRegisters);
            logger.info("Add application registers: " + ssoClientApplicationRegisters);
        }
    }

    public void setPermitAllAuthorizationManager(AuthorizationManager<HttpServletRequest> permitAllAuthorizationManager) {
        this.permitAllAuthorizationManager = permitAllAuthorizationManager;
    }

    private boolean isPermitAllRequest(HttpServletRequest req) {
        if (permitAllAuthorizationManager != null) {
            AnonymousAuthenticationToken anonymousToken = new AnonymousAuthenticationToken(anonymousKey, "anonymousUser", anonymousAuthorities);
            anonymousToken.setDetails(authenticationDetailsSource.buildDetails(req));

            AuthorizationDecision decision = permitAllAuthorizationManager.check(() -> anonymousToken, req);
            return decision != null && decision.isGranted();
        }
        return false;
    }

    private UserPrincipal authenticateUser(HttpServletRequest req, T tokenData) {
        UserData userData = processTokenData(req, tokenData);

        logger.debug("User principal creation");
        User user = new User();
        user.setLogin(userData.login);
        UserPrincipal userPrincipal = new UserPrincipal(user);
        List<UserGrantedAuthority> userGrantedAuthorities = userData.authorities.stream()
                .map(UserGrantedAuthority::new)
                .collect(Collectors.toList());

        UsernamePasswordAuthenticationToken authentication = UsernamePasswordAuthenticationToken
                .authenticated(userPrincipal, null, userGrantedAuthorities);
        authentication.setDetails(authenticationDetailsSource.buildDetails(req));

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);

        return userPrincipal;
    }

    static class UserData {
        private final String login;
        private final List<String> authorities;

        public UserData(String login, List<String> authorities) {
            this.login = login;
            this.authorities = authorities;
        }
    }
}

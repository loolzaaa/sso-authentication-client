package ru.loolzaaa.sso.client.core.security.filter;

import io.jsonwebtoken.ClaimJwtException;
import io.jsonwebtoken.Claims;
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
import org.springframework.security.web.util.UrlUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import ru.loolzaaa.sso.client.core.application.SsoClientApplicationRegister;
import ru.loolzaaa.sso.client.core.context.UserService;
import ru.loolzaaa.sso.client.core.model.User;
import ru.loolzaaa.sso.client.core.model.UserGrantedAuthority;
import ru.loolzaaa.sso.client.core.model.UserPrincipal;
import ru.loolzaaa.sso.client.core.security.CookieName;
import ru.loolzaaa.sso.client.core.util.JWTUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

public class JwtTokenFilter extends OncePerRequestFilter {

    private final String applicationName;

    private final String entryPointAddress;

    private final String refreshTokenURI;

    private final JWTUtils jwtUtils;

    private final UserService userService;

    private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

    private final List<SsoClientApplicationRegister> ssoClientApplicationRegisters = new ArrayList<>();

    private final String anonymousKey = UUID.randomUUID().toString();
    private final List<GrantedAuthority> anonymousAuthorities = AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS");
    private AuthorizationManager<HttpServletRequest> permitAllAuthorizationManager;

    public JwtTokenFilter(String applicationName, String entryPointAddress, String refreshTokenURI, JWTUtils jwtUtils,
                          UserService userService) {
        this.applicationName = applicationName;
        this.entryPointAddress = entryPointAddress;
        this.refreshTokenURI = refreshTokenURI;
        this.jwtUtils = jwtUtils;
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

        String accessToken = extractAccessToken(req);
        if (accessToken == null) {
            logger.trace("Access token is null");

            chain.doFilter(req, resp);
            return;
        }

        Claims claims = validateAccessToken(accessToken);

        if (claims != null) {
            UserPrincipal userPrincipal = processUserAuthorities(req, claims);

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
            logger.debug("Invalid access token, try to refresh it");

            logger.trace("Remove invalid access token cookie");
            removeInvalidAccessTokenCookie(req, resp);

            if (isAjaxRequest(req)) {
                logger.debug("Ajax request detected. Refresh via Auth Server API");

                resp.setHeader("X-SSO-FP", entryPointAddress + "/api/refresh/ajax");
                resp.setHeader("X-SSO-APP", applicationName);
                resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
            } else {
                logger.debug("Browser request detected. Refresh via redirect to SSO " + refreshTokenURI);

                String continueParamValue = UrlUtils.buildFullRequestUrl(req);
                String continueUrl = Base64.getUrlEncoder().encodeToString(continueParamValue.getBytes(StandardCharsets.UTF_8));
                UriComponents continueUri = UriComponentsBuilder.fromHttpUrl(entryPointAddress + refreshTokenURI)
                        .queryParam("app", applicationName)
                        .queryParam("continue", continueUrl)
                        .build();

                resp.sendRedirect(continueUri.toString());
            }
        }
    }

    public void addApplicationRegisters(List<SsoClientApplicationRegister> applicationRegisters) {
        if (applicationRegisters != null && !applicationRegisters.isEmpty()) {
            ssoClientApplicationRegisters.addAll(applicationRegisters);
            logger.info("Add application registers: " + ssoClientApplicationRegisters);
        }
    }

    public void setPermitAllAuthorizationManager(AuthorizationManager<HttpServletRequest> permitAllAuthorizationManager) {
        this.permitAllAuthorizationManager = permitAllAuthorizationManager;
    }

    private UserPrincipal processUserAuthorities(HttpServletRequest req, Claims claims) {
        logger.debug("Application level authorization check");
        String login = claims.get("login", String.class);
        List<String> authorities;
        try {
            authorities = claims.get("authorities", List.class);
            if (authorities == null) {
                logger.debug("There is no authorities for " + login);
                authorities = new ArrayList<>(0);
            }
        } catch (Exception e) {
            logger.warn("Error while get authorities from access token claim: ", e);
            authorities = new ArrayList<>(0);
        }

        logger.debug("User principal creation");
        User user = new User();
        user.setLogin(login);
        UserPrincipal userPrincipal = new UserPrincipal(user);
        List<UserGrantedAuthority> userGrantedAuthorities = authorities.stream()
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

    private boolean isPermitAllRequest(HttpServletRequest req) {
        if (permitAllAuthorizationManager != null) {
            AnonymousAuthenticationToken anonymousToken = new AnonymousAuthenticationToken(anonymousKey, "anonymousUser", anonymousAuthorities);
            anonymousToken.setDetails(authenticationDetailsSource.buildDetails(req));

            AuthorizationDecision decision = permitAllAuthorizationManager.check(() -> anonymousToken, req);
            return decision != null && decision.isGranted();
        }
        return false;
    }

    private String extractAccessToken(HttpServletRequest req) {
        if (req.getCookies() != null) {
            for (Cookie c : req.getCookies()) {
                if (CookieName.ACCESS.getName().equals(c.getName())) {
                    return c.getValue();
                }
            }
        }
        return null;
    }

    private Claims validateAccessToken(String accessToken) {
        try {
            Claims claims = jwtUtils.parserEnforceAccessToken(accessToken).getBody();
            String login = claims.get("login", String.class);
            logger.debug(String.format("Access token for user [%s] validated", login));
            return claims;
        } catch (ClaimJwtException e) {
            logger.trace(String.format("Access token for user [%s] is expired", e.getClaims().get("login")));
        } catch (Exception e) {
            logger.warn("Parsed access token: " + accessToken);
            logger.warn("Undeclared exception while parse access token: " + e.getMessage());
        }
        return null;
    }

    private void removeInvalidAccessTokenCookie(HttpServletRequest req, HttpServletResponse resp) {
        Cookie c = new Cookie(CookieName.ACCESS.getName(), null);
        c.setHttpOnly(true);
        c.setSecure(req.isSecure());
        c.setPath(req.getContextPath().length() > 0 ? req.getContextPath() : "/");
        c.setMaxAge(0);
        resp.addCookie(c);
    }

    private boolean isAjaxRequest(HttpServletRequest request) {
        String acceptHeader = request.getHeader("Accept");
        return acceptHeader != null && acceptHeader.toLowerCase().contains("application/json");
    }
}

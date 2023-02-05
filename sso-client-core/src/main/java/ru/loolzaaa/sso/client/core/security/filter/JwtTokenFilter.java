package ru.loolzaaa.sso.client.core.security.filter;

import io.jsonwebtoken.ClaimJwtException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import ru.loolzaaa.sso.client.core.application.SsoClientApplicationRegister;
import ru.loolzaaa.sso.client.core.context.UserService;
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

public class JwtTokenFilter extends OncePerRequestFilter {

    private final String entryPointAddress;

    private final String refreshTokenURI;

    private final JWTUtils jwtUtils;

    private final UserService userService;

    private final AccessDeniedHandler accessDeniedHandler;

    private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

    private final List<SsoClientApplicationRegister> ssoClientApplicationRegisters = new ArrayList<>();

    private final String anonymousKey = UUID.randomUUID().toString();
    private final List<GrantedAuthority> anonymousAuthorities = AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS");
    private AuthorizationManager<HttpServletRequest> permitAllAuthorizationManager;

    public JwtTokenFilter(String entryPointAddress, String refreshTokenURI, JWTUtils jwtUtils,
                          UserService userService, AccessDeniedHandler accessDeniedHandler) {
        this.entryPointAddress = entryPointAddress;
        this.refreshTokenURI = refreshTokenURI;
        this.jwtUtils = jwtUtils;
        this.userService = userService;
        this.accessDeniedHandler = accessDeniedHandler;
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

        String login = validateAccessToken(accessToken);

        if (login != null) {
            logger.debug("Update security context");
            UserPrincipal userDetails;
            try {
                userDetails = userService.getUserFromServerByUsername(login);
            } catch (AccessDeniedException e) {
                accessDeniedHandler.handle(req, resp, e);
                return;
            }

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    userDetails,
                    null,
                    userDetails.getAuthorities());
            authentication.setDetails(authenticationDetailsSource.buildDetails(req));

            SecurityContextHolder.getContext().setAuthentication(authentication);

            userService.saveRequestUser(userDetails);

            try {
                for (SsoClientApplicationRegister applicationRegister : ssoClientApplicationRegisters) {
                    applicationRegister.register(userDetails);
                }
                chain.doFilter(req, resp);
            } finally {
                userService.clearRequestUser();
            }
        } else {
            logger.debug("Invalid access token, try to refresh it");

            logger.trace("Remove invalid access token cookie");
            Cookie c = new Cookie(CookieName.ACCESS.getName(), null);
            c.setHttpOnly(true);
            c.setSecure(req.isSecure());
            c.setPath(req.getContextPath().length() > 0 ? req.getContextPath() : "/");
            c.setMaxAge(0);
            resp.addCookie(c);

            if (isAjaxRequest(req)) {
                logger.debug("Ajax request detected. Refresh via Auth Server API");

                resp.setHeader("fp_request", entryPointAddress + "/api/refresh/ajax");
                resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
            } else {
                logger.debug("Browser request detected. Refresh via redirect to " + refreshTokenURI);

                String continueParamValue = UrlUtils.buildFullRequestUrl(req);
                String continueUrl = Base64.getUrlEncoder().encodeToString(continueParamValue.getBytes(StandardCharsets.UTF_8));
                UriComponents continueUri = UriComponentsBuilder.fromHttpUrl(entryPointAddress + refreshTokenURI)
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

    private String validateAccessToken(String accessToken) {
        String login = null;
        try {
            Jws<Claims> claims = jwtUtils.parserEnforceAccessToken(accessToken);
            login = (String) claims.getBody().get("login");

            logger.debug(String.format("Access token for user [%s] validated", login));
        } catch (ClaimJwtException e) {
            logger.trace(String.format("Access token for user [%s] is expired", e.getClaims().get("login")));
        } catch (Exception e) {
            logger.warn("Parsed access token: " + accessToken);
            logger.warn("Undeclared exception while parse access token: " + e.getMessage());
        }
        return login;
    }

    private boolean isAjaxRequest(HttpServletRequest request) {
        String acceptHeader = request.getHeader("Accept");
        return acceptHeader != null && acceptHeader.toLowerCase().contains("application/json");
    }
}

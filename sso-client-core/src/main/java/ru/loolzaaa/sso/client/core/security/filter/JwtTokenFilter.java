package ru.loolzaaa.sso.client.core.security.filter;

import io.jsonwebtoken.ClaimJwtException;
import io.jsonwebtoken.Claims;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import ru.loolzaaa.sso.client.core.context.UserService;
import ru.loolzaaa.sso.client.core.security.CookieName;
import ru.loolzaaa.sso.client.core.util.JWTUtils;

import javax.servlet.FilterChain;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class JwtTokenFilter extends AbstractTokenFilter<Claims> {

    private final String applicationName;

    private final String entryPointAddress;

    private final String refreshTokenURI;

    private final JWTUtils jwtUtils;

    public JwtTokenFilter(String applicationName, String entryPointAddress, String refreshTokenURI, JWTUtils jwtUtils,
                          UserService userService) {
        super(userService);
        this.applicationName = applicationName;
        this.entryPointAddress = entryPointAddress;
        this.refreshTokenURI = refreshTokenURI;
        this.jwtUtils = jwtUtils;
    }

    @Override
    protected Claims extractTokenData(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String accessToken = extractAccessToken(req);
        if (accessToken == null) {
            logger.trace("Access token is null");
            throw new IllegalArgumentException("Access token is null");
        }
        return validateAccessToken(accessToken);
    }

    @Override
    protected UserData processTokenData(HttpServletRequest req, Claims tokenData) {
        logger.debug("Application level authorization check");
        String login = tokenData.get("login", String.class);
        List<String> authorities;
        try {
            authorities = tokenData.get("authorities", List.class);
            if (authorities == null) {
                logger.debug("There is no authorities for " + login);
                authorities = new ArrayList<>(0);
            }
        } catch (Exception e) {
            logger.warn("Error while get authorities from access token claim: ", e);
            authorities = new ArrayList<>(0);
        }
        return new UserData(login, authorities);
    }

    @Override
    protected void handleInvalidTokenData(HttpServletRequest req, HttpServletResponse resp,
                                          FilterChain chain) throws IOException {
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

package ru.loolzaaa.sso.client.core.filter;

import io.jsonwebtoken.ClaimJwtException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import ru.loolzaaa.sso.client.core.JWTUtils;
import ru.loolzaaa.sso.client.core.UserService;
import ru.loolzaaa.sso.client.core.helper.SsoClientApplicationRegister;
import ru.loolzaaa.sso.client.core.model.UserPrincipal;

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

public class JwtTokenFilter extends OncePerRequestFilter {

    private final String entryPointAddress;

    private final String refreshTokenURI;

    private final JWTUtils jwtUtils;

    private final UserService userService;

    private final List<SsoClientApplicationRegister> ssoClientApplicationRegisters = new ArrayList<>();

    public JwtTokenFilter(String entryPointAddress, String refreshTokenURI, JWTUtils jwtUtils, UserService userService) {
        this.entryPointAddress = entryPointAddress;
        this.refreshTokenURI = refreshTokenURI;
        this.jwtUtils = jwtUtils;
        this.userService = userService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse resp,
                                    FilterChain chain) throws ServletException, IOException {
        String accessToken = null;
        if (req.getCookies() != null) {
            for (Cookie c : req.getCookies()) {
                if ("_t_access".equals(c.getName())) {
                    accessToken = c.getValue();
                }
            }
        }

        if (accessToken == null) {
            logger.trace("Access token is null");

            chain.doFilter(req, resp);
            return;
        }

        String login = null;
        try {
            Jws<Claims> claims = jwtUtils.parserEnforceAccessToken(accessToken);
            login = (String) claims.getBody().get("login");

            logger.debug(String.format("Access token for user [%s] validated", login));
        } catch (ClaimJwtException e) {
            logger.trace(String.format("Access token for user [%s] is expired", e.getClaims().get("login")));
        } catch (Exception ignored) {}

        if (login != null) {
            logger.debug("Update security context");
            UserPrincipal userDetails = userService.getUserFromServerByUsername(login);

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    userDetails,
                    null,
                    userDetails.getAuthorities());
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(req));

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
            Cookie c = new Cookie("_t_access", null);
            c.setHttpOnly(true);
            c.setSecure(req.isSecure());
            c.setPath(req.getContextPath().length() > 0 ? req.getContextPath() : "/");
            c.setMaxAge(0);
            resp.addCookie(c);

            String acceptHeader = req.getHeader("Accept");
            if (acceptHeader != null && acceptHeader.toLowerCase().contains("application/json")) {
                logger.debug("Ajax request detected. Refresh via Auth Server API");

                resp.setHeader("fp_request", entryPointAddress + "/api/refresh/ajax");
                resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
            } else {
                logger.debug("Browser request detected. Refresh via redirect to " + refreshTokenURI);

                String continueParamValue = UrlUtils.buildFullRequestUrl(req);
                byte[] bytes = Base64.getUrlEncoder().encode(continueParamValue.getBytes(StandardCharsets.UTF_8));
                UriComponents continueUri = UriComponentsBuilder.fromHttpUrl(entryPointAddress + refreshTokenURI)
                        .queryParam("continue", new String((bytes)))
                        .build();

                resp.sendRedirect(continueUri.toString());
            }
        }
    }

    public void addApplicationRegister(SsoClientApplicationRegister applicationRegister) {
        if (applicationRegister == null) {
            throw new NullPointerException("Application register cannot be null");
        }
        ssoClientApplicationRegisters.add(applicationRegister);
    }
}

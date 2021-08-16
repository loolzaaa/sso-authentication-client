package ru.loolzaaa.authclientexample.config.security.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import ru.loolzaaa.authclientexample.config.security.JWTUtils;
import ru.loolzaaa.authclientexample.config.security.SecurityConfig;
import ru.loolzaaa.authclientexample.services.UserService;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@RequiredArgsConstructor
public class JwtTokenFilter extends OncePerRequestFilter {

    private final String refreshTokenURI;

    private final JWTUtils jwtUtils;

    private final UserService userService;

    private static long serverSkew;

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
            Jws<Claims> claims = jwtUtils.parserEnforceAccessToken(accessToken, serverSkew);
            login = (String) claims.getBody().get("login");

            logger.debug(String.format("Access token for user [%s] validated", login));
        } catch (Exception ignored) {}

        if (login != null) {
            logger.debug("Check user for authentication and update if necessary");
            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                logger.trace("Update SecurityContext");

                UserDetails userDetails = userService.getUserByUsername(login);

                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(req));

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

            chain.doFilter(req, resp);
        } else {
            logger.debug("Invalid access token, try to refresh it");

            String acceptHeader = req.getHeader("Accept");
            if (acceptHeader != null && acceptHeader.toLowerCase().contains("application/json")) {
                logger.debug("Ajax request detected. Refresh via Auth Server API");

                resp.setHeader("fp_request", SecurityConfig.ENTRY_POINT_ADDR + "/api/refresh/ajax");
                resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
            } else {
                logger.debug("Browser request detected. Refresh via redirect to " + refreshTokenURI);

                String continueParamValue = UrlUtils.buildFullRequestUrl(req);
                byte[] bytes = Base64.getUrlEncoder().encode(continueParamValue.getBytes(StandardCharsets.UTF_8));
                UriComponents continueUri = UriComponentsBuilder.fromHttpUrl(SecurityConfig.ENTRY_POINT_ADDR + refreshTokenURI)
                        .queryParam("continue", new String((bytes)))
                        .build();

                resp.sendRedirect(continueUri.toString());
            }
        }
    }

    public static void setServerSkew(long serverSkew) {
        JwtTokenFilter.serverSkew = serverSkew;
    }
}

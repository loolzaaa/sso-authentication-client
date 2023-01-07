package ru.loolzaaa.sso.client.core.security.filter;

import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.util.UriComponentsBuilder;
import ru.loolzaaa.sso.client.core.security.CookieName;
import ru.loolzaaa.sso.client.core.util.JWTUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class QueryJwtTokenFilter extends GenericFilterBean {

    private static final String SERVER_TIME_PARAM_NAME = "serverTime";

    private static final String SERVER_TIME_HEADER_NAME = "X-SSO-TIME";

    private static final String TOKEN_PARAM_NAME = "token";

    private final JWTUtils jwtUtils;

    public QueryJwtTokenFilter(JWTUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) resp;

        String serverTimeParam = request.getParameter(SERVER_TIME_PARAM_NAME);
        if (serverTimeParam == null) {
            serverTimeParam = request.getHeader(SERVER_TIME_HEADER_NAME);
        }
        if (serverTimeParam != null) {
            long serverTime;
            try {
                serverTime = Long.parseLong(serverTimeParam);
            } catch (Exception e) {
                logger.warn("Cannot parse server time from authentication server", e);
                serverTime = System.currentTimeMillis();
            }
            jwtUtils.setServerSkew(serverTime - System.currentTimeMillis());
        }

        String rfidParameter = request.getParameter(CookieName.RFID.getName());
        if (rfidParameter != null) {
            Cookie cookie = new Cookie(CookieName.RFID.getName(), "");
            cookie.setHttpOnly(false);
            cookie.setSecure(req.isSecure());
            cookie.setPath(request.getContextPath().length() > 0 ? request.getContextPath() : "/");
            response.addCookie(cookie);
        }

        String queryToken = request.getParameter(TOKEN_PARAM_NAME);
        if (queryToken != null) {
            Cookie cookie = new Cookie(CookieName.ACCESS.getName(), queryToken);
            cookie.setHttpOnly(true);
            cookie.setSecure(req.isSecure());
            cookie.setPath(request.getContextPath().length() > 0 ? request.getContextPath() : "/");
            response.addCookie(cookie);

            String acceptHeader = request.getHeader("Accept");
            if (acceptHeader != null && acceptHeader.toLowerCase().contains("application/json")) {
                logger.debug("Ajax request detected. Not need to redirect for param clean");

                response.setStatus(HttpServletResponse.SC_OK);
            } else {
                logger.debug("Browser request detected. Need to redirect for param clean");

                UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromHttpUrl(request.getRequestURL().toString());
                request.getParameterNames().asIterator().forEachRemaining(param -> {
                    if (!isParamNeedToClear(param)) {
                        uriBuilder.queryParam(param, req.getParameter(param));
                    }
                });

                response.sendRedirect(uriBuilder.toUriString());
            }
        } else {
            chain.doFilter(req, resp);
        }
    }

    private boolean isParamNeedToClear(String paramName) {
        return TOKEN_PARAM_NAME.equals(paramName)
                || SERVER_TIME_PARAM_NAME.equals(paramName)
                || CookieName.RFID.getName().equals(paramName);
    }
}
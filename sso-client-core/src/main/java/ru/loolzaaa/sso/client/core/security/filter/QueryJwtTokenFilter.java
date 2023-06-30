package ru.loolzaaa.sso.client.core.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.util.UriComponentsBuilder;
import ru.loolzaaa.sso.client.core.security.CookieName;
import ru.loolzaaa.sso.client.core.util.JWTUtils;

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

        updateServerTime(request);

        attemptToAddRfidCookie(request, response);

        String queryToken = request.getParameter(TOKEN_PARAM_NAME);
        if (queryToken != null) {
            addCookieToResponse(request, response, CookieName.ACCESS.getName(), queryToken, true);

            if (isAjaxRequest(request)) {
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

    private void updateServerTime(HttpServletRequest request) {
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
    }

    private void attemptToAddRfidCookie(HttpServletRequest request, HttpServletResponse response) {
        String rfidParameter = request.getParameter(CookieName.RFID.getName());
        if (rfidParameter != null) {
            addCookieToResponse(request, response, CookieName.RFID.getName(), "", false);
        }
    }

    private void addCookieToResponse(HttpServletRequest request, HttpServletResponse response,
                                     String cookieName, String cookieValue, boolean httpOnly) {
        Cookie cookie = new Cookie(cookieName, cookieValue);
        cookie.setHttpOnly(httpOnly);
        cookie.setSecure(request.isSecure());
        cookie.setPath(request.getContextPath().length() > 0 ? request.getContextPath() : "/");
        response.addCookie(cookie);
    }

    private boolean isAjaxRequest(HttpServletRequest request) {
        String acceptHeader = request.getHeader("Accept");
        return acceptHeader != null && acceptHeader.toLowerCase().contains("application/json");
    }

    private boolean isParamNeedToClear(String paramName) {
        return TOKEN_PARAM_NAME.equals(paramName)
                || SERVER_TIME_PARAM_NAME.equals(paramName)
                || CookieName.RFID.getName().equals(paramName);
    }


}
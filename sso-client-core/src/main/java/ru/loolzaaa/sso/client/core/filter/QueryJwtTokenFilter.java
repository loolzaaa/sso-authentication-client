package ru.loolzaaa.sso.client.core.filter;

import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.util.UriComponentsBuilder;
import ru.loolzaaa.sso.client.core.JWTUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class QueryJwtTokenFilter extends GenericFilterBean {

    private final JWTUtils jwtUtils;

    public QueryJwtTokenFilter(JWTUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) resp;

        String queryServerTime = request.getParameter("serverTime");
        if (queryServerTime != null) {
            long serverTime;
            try {
                serverTime = Long.parseLong(queryServerTime);
            } catch (Exception e) {
                logger.warn("Cannot parse server time from authentication server", e);
                serverTime = System.currentTimeMillis();
            }
            jwtUtils.setServerSkew(serverTime - System.currentTimeMillis());
        }

        String queryToken = request.getParameter("token");
        if (queryToken != null) {
            Cookie cookie = new Cookie("_t_access", queryToken);
            cookie.setHttpOnly(true);
            cookie.setSecure(req.isSecure());
            cookie.setPath(request.getContextPath() + "/");
            response.addCookie(cookie);

            UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromHttpUrl(request.getRequestURL().toString());
            request.getParameterNames().asIterator().forEachRemaining(param -> {
                if (!"token".equals(param) && !"serverTime".equals(param)) {
                    uriBuilder.queryParam(param, req.getParameter(param));
                }
            });

            String acceptHeader = request.getHeader("Accept");
            if (acceptHeader != null && acceptHeader.toLowerCase().contains("application/json")) {
                logger.debug("Ajax request detected. Not need to redirect for param clean");

                response.setStatus(HttpServletResponse.SC_OK);
            } else {
                logger.debug("Browser request detected. Need to redirect for param clean");

                response.sendRedirect(uriBuilder.toUriString());
            }
        } else {
            chain.doFilter(req, resp);
        }
    }
}
package ru.loolzaaa.authclientexample.config.security.filter;

import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class QueryJwtTokenFilter extends GenericFilterBean {
    @Override
    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) resp;

        String queryServerTime = request.getParameter("serverTime");
        if (queryServerTime != null) {
            long serverTime;
            try {
                serverTime = Long.parseLong(queryServerTime);
            } catch (Exception ignored) {
                //TODO: log it
                serverTime = System.currentTimeMillis();
            }
            JwtTokenFilter.setServerSkew(serverTime - System.currentTimeMillis());
        }

        String queryToken = request.getParameter("token");
        //TODO: decode token
        if (queryToken != null) {
            Cookie cookie = new Cookie("_t_access", queryToken);
            cookie.setHttpOnly(true);
            cookie.setSecure(req.isSecure());
            cookie.setPath("/");
            response.addCookie(cookie);

            UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromHttpUrl(request.getRequestURL().toString());
            request.getParameterNames().asIterator().forEachRemaining(param -> {
                if (!"token".equals(param) && !"serverTime".equals(param)) {
                    uriBuilder.queryParam(param, req.getParameter(param));
                }
            });

            String acceptHeader = request.getHeader("Accept");
            if (acceptHeader != null && acceptHeader.toLowerCase().contains("application/json")) {
                //TODO: log it
                response.setStatus(HttpServletResponse.SC_OK);
            } else {
                response.sendRedirect(uriBuilder.toUriString());
            }
        } else {
            chain.doFilter(req, resp);
        }
    }
}

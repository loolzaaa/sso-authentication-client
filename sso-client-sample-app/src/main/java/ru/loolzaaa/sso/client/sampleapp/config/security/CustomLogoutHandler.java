package ru.loolzaaa.sso.client.sampleapp.config.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Component
public class CustomLogoutHandler implements LogoutHandler {
    @Override
    public void logout(HttpServletRequest req, HttpServletResponse resp, Authentication auth) {
        ///////////////////////////////////////////////
        //
        // Application-specific logout ...
        //
        ///////////////////////////////////////////////
    }
}

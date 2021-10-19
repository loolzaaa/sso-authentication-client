package ru.loolzaaa.sso.client.core;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.impl.FixedClock;
import io.jsonwebtoken.impl.TextCodec;
import org.springframework.jmx.export.annotation.ManagedAttribute;
import org.springframework.jmx.export.annotation.ManagedResource;
import org.springframework.stereotype.Component;

import java.util.Date;

@ManagedResource
@Component
public class JWTUtils {

    private String accessSecretKey = "dUYzUFY4UVN6MkpXenpKbThzaFhmd0U2eElOdFlzZmQzZGN4Sk8xTTA5RDBWR014RElpTElkNndtTmYyaDRkMQ==";

    private long serverSkew;

    public Jws<Claims> parserEnforceAccessToken(String jwt) {
        return Jwts.parser()
                .setClock(new FixedClock(new Date(System.currentTimeMillis() + serverSkew)))
                .setAllowedClockSkewSeconds(30)
                .setSigningKey(getHS256SecretBytes(accessSecretKey))
                .parseClaimsJws(jwt);
    }

    private byte[] getHS256SecretBytes(String key) {
        return TextCodec.BASE64.decode(key);
    }

    @ManagedAttribute
    public String getAccessSecretKey() {
        return accessSecretKey;
    }

    @ManagedAttribute
    public void setAccessSecretKey(String accessSecretKey) {
        this.accessSecretKey = accessSecretKey;
    }

    public void setServerSkew(long serverSkew) {
        this.serverSkew = serverSkew;
    }
}

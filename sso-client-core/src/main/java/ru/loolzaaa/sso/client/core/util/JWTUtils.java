package ru.loolzaaa.sso.client.core.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.impl.FixedClock;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;
import org.springframework.util.ResourceUtils;
import org.springframework.util.StringUtils;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

@Component
public class JWTUtils {

    private final Key publicKey;

    private long serverSkew;

    public JWTUtils(@Value("${sso.client.jwt.key-path:}") String keyPath) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        String publicKeyPath = "keystore/public.key";
        byte[] publicKeyBytes;
        if (StringUtils.hasText(keyPath)) {
            publicKeyPath = keyPath + "/public.key";

            File publicKeyFile = ResourceUtils.getFile(publicKeyPath);
            publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());
        } else {
            InputStream publicKeyStream = new ClassPathResource(publicKeyPath).getInputStream();
            try (publicKeyStream) {
                publicKeyBytes = publicKeyStream.readAllBytes();
            }
        }

        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        this.publicKey = keyFactory.generatePublic(publicKeySpec);
    }

    public Jws<Claims> parserEnforceAccessToken(String jwt) {
        return Jwts.parser()
                .setAllowedClockSkewSeconds(10)
                .setClock(new FixedClock(new Date(System.currentTimeMillis() + serverSkew)))
                .setSigningKey(publicKey)
                .parseClaimsJws(jwt);
    }

    public void validateToken(String jwt) {
        Jwts.parser()
                .setClock(new FixedClock(new Date(System.currentTimeMillis() + serverSkew)))
                .setSigningKey(publicKey)
                .parseClaimsJws(jwt);
    }

    public void setServerSkew(long serverSkew) {
        this.serverSkew = serverSkew;
    }
}

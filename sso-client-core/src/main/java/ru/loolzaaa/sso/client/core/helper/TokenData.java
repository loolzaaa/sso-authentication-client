package ru.loolzaaa.sso.client.core.helper;

public class TokenData {

    private String accessToken;
    private String refreshToken;

    public TokenData(String accessToken, String refreshToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

    public void resetValues() {
        this.accessToken = null;
        this.refreshToken = null;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }
}

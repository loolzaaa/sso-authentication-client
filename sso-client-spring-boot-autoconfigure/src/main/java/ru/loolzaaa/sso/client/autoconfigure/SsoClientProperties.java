package ru.loolzaaa.sso.client.autoconfigure;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "sso.client")
public class SsoClientProperties {

    private boolean enabled = true;

    private String applicationName;

    private String refreshTokenUri = "/trefresh";

    private String entryPointAddress;
    private String entryPointUri;

    private String basicLogin = "SERVICE";
    private String basicPassword = "PASSWORD";

    private String revokeUsername = "REVOKE_TOKEN_USER";
    private String revokePassword = "REVOKE_TOKEN_USER_PASSWORD";

    private final Receiver receiver = new Receiver();

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getApplicationName() {
        return applicationName;
    }

    public void setApplicationName(String applicationName) {
        this.applicationName = applicationName;
    }

    public String getRefreshTokenUri() {
        return refreshTokenUri;
    }

    public void setRefreshTokenUri(String refreshTokenUri) {
        this.refreshTokenUri = refreshTokenUri;
    }

    public String getEntryPointAddress() {
        return entryPointAddress;
    }

    public void setEntryPointAddress(String entryPointAddress) {
        this.entryPointAddress = entryPointAddress;
    }

    public String getEntryPointUri() {
        return entryPointUri;
    }

    public void setEntryPointUri(String entryPointUri) {
        this.entryPointUri = entryPointUri;
    }

    public String getBasicLogin() {
        return basicLogin;
    }

    public void setBasicLogin(String basicLogin) {
        this.basicLogin = basicLogin;
    }

    public String getBasicPassword() {
        return basicPassword;
    }

    public void setBasicPassword(String basicPassword) {
        this.basicPassword = basicPassword;
    }

    public String getRevokeUsername() {
        return revokeUsername;
    }

    public void setRevokeUsername(String revokeUsername) {
        this.revokeUsername = revokeUsername;
    }

    public String getRevokePassword() {
        return revokePassword;
    }

    public void setRevokePassword(String revokePassword) {
        this.revokePassword = revokePassword;
    }

    public Receiver getReceiver() {
        return receiver;
    }

    public static class Receiver {
        private String username;
        private String password;
        private String fingerprint;

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public String getFingerprint() {
            return fingerprint;
        }

        public void setFingerprint(String fingerprint) {
            this.fingerprint = fingerprint;
        }
    }
}

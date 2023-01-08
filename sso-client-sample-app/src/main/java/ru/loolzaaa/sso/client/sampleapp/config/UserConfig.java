package ru.loolzaaa.sso.client.sampleapp.config;

import ru.loolzaaa.sso.client.core.model.BaseUserConfig;

public class UserConfig extends BaseUserConfig {
    private String someSetting;

    public String getSomeSetting() {
        return someSetting;
    }

    public void setSomeSetting(String someSetting) {
        this.someSetting = someSetting;
    }
}

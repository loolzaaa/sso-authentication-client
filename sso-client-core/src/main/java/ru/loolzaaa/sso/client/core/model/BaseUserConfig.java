package ru.loolzaaa.sso.client.core.model;

import java.io.Serializable;
import java.util.List;

public class BaseUserConfig implements Serializable {

    private static final long serialVersionUID = 5974906752020741943L;

    private List<String> roles;
    private List<String> privileges;
    private Temporary temporary;

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }

    public List<String> getPrivileges() {
        return privileges;
    }

    public void setPrivileges(List<String> privileges) {
        this.privileges = privileges;
    }

    public Temporary getTemporary() {
        return temporary;
    }

    public void setTemporary(Temporary temporary) {
        this.temporary = temporary;
    }
}

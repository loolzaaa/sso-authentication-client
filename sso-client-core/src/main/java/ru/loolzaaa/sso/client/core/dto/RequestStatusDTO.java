package ru.loolzaaa.sso.client.core.dto;

public class RequestStatusDTO {

    private static final long serialVersionUID = 6409161491520023550L;

    private String status;
    private String text;

    public RequestStatusDTO() {
    }

    public RequestStatusDTO(String status, String text) {
        this.status = status;
        this.text = text;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getText() {
        return text;
    }

    public void setText(String text) {
        this.text = text;
    }
}

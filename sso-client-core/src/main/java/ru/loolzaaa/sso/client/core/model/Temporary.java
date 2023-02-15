package ru.loolzaaa.sso.client.core.model;

import java.io.Serializable;
import java.time.LocalDate;

public class Temporary implements Serializable {

    private static final long serialVersionUID = 5908438692192303319L;

    private String originTabNumber;
    private LocalDate dateFrom;
    private LocalDate dateTo;

    public String getOriginTabNumber() {
        return originTabNumber;
    }

    public void setOriginTabNumber(String originTabNumber) {
        this.originTabNumber = originTabNumber;
    }

    public LocalDate getDateFrom() {
        return dateFrom;
    }

    public void setDateFrom(LocalDate dateFrom) {
        this.dateFrom = dateFrom;
    }

    public LocalDate getDateTo() {
        return dateTo;
    }

    public void setDateTo(LocalDate dateTo) {
        this.dateTo = dateTo;
    }
}

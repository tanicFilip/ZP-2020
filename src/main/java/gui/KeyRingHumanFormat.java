package gui;

import java.util.Date;

public class KeyRingHumanFormat {

    private String name;
    private String email;
    private Date dateCreated;
    private Date dateExpires;
    private String masterPublicKeyFingerprint;

    public KeyRingHumanFormat() {
    }

    public KeyRingHumanFormat(String name, String email, Date dateCreated, Date dateExpires, String masterPublicKeyFingerprint) {
        this.name = name;
        this.email = email;
        this.dateCreated = dateCreated;
        this.dateExpires = dateExpires;
        this.masterPublicKeyFingerprint = masterPublicKeyFingerprint;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public Date getDateCreated() {
        return dateCreated;
    }

    public void setDateCreated(Date dateCreated) {
        this.dateCreated = dateCreated;
    }

    public Date getDateExpires() {
        return dateExpires;
    }

    public void setDateExpires(Date dateExpires) {
        this.dateExpires = dateExpires;
    }

    public String getMasterPublicKeyFingerprint() {
        return masterPublicKeyFingerprint;
    }

    public void setMasterPublicKeyFingerprint(String masterPublicKeyFingerprint) {
        this.masterPublicKeyFingerprint = masterPublicKeyFingerprint;
    }

    @Override
    public String toString() {
        return "KeyRingHumanFormat{" +
                "name='" + name + '\'' +
                ", email='" + email + '\'' +
                ", dateCreated=" + dateCreated +
                ", dateExpires=" + dateExpires +
                ", keyFingerprint=" + masterPublicKeyFingerprint +
                '}';
    }

}

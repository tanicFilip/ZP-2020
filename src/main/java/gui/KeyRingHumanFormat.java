package gui;

import java.util.Arrays;
import java.util.Date;

public class KeyRingHumanFormat {

    private String name;
    private String email;
    private Date dateCreated;
    private Date dateExpires;
    private byte[] keyFingerprint;

    public KeyRingHumanFormat() {
    }

    public KeyRingHumanFormat(String name, String email, Date dateCreated, Date dateExpires, byte[] keyFingerprint) {
        this.name = name;
        this.email = email;
        this.dateCreated = dateCreated;
        this.dateExpires = dateExpires;
        this.keyFingerprint = keyFingerprint;
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

    public byte[] getKeyFingerprint() {
        return keyFingerprint;
    }

    public void setKeyFingerprint(byte[] keyFingerprint) {
        this.keyFingerprint = keyFingerprint;
    }

    @Override
    public String toString() {
        return "KeyRingHumanFormat{" +
                "name='" + name + '\'' +
                ", email='" + email + '\'' +
                ", dateCreated=" + dateCreated +
                ", dateExpires=" + dateExpires +
                ", keyFingerprint=" + Arrays.toString(keyFingerprint) +
                '}';
    }

}

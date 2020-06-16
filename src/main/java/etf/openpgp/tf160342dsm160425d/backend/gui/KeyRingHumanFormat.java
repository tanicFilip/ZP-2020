package etf.openpgp.tf160342dsm160425d.backend.gui;

import java.util.Date;

public class KeyRingHumanFormat {

    public enum KeyType {
        SECRET, PUBLIC, PAIR
    }

    private String name;
    private String email;
    private Date dateCreated;
    private Date dateExpires;
    private String masterKeyFingerprint;
    private KeyType keyType;

    public KeyRingHumanFormat() {
    }

    public KeyRingHumanFormat(String name, String email, Date dateCreated, Date dateExpires, String masterKeyFingerprint) {
        this.name = name;
        this.email = email;
        this.dateCreated = dateCreated;
        this.dateExpires = dateExpires;
        this.masterKeyFingerprint = masterKeyFingerprint;
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

    public String getMasterKeyFingerprint() {
        return masterKeyFingerprint;
    }

    public void setMasterKeyFingerprint(String masterKeyFingerprint) {
        this.masterKeyFingerprint = masterKeyFingerprint;
    }

    public KeyType getKeyType() {
        return keyType;
    }

    public void setKeyType(KeyType keyType) {
        this.keyType = keyType;
    }

    @Override
    public String toString() {
        return "KeyRingHumanFormat{" +
                "name='" + name + '\'' +
                ", email='" + email + '\'' +
                ", dateCreated=" + dateCreated +
                ", dateExpires=" + dateExpires +
                ", keyFingerprint=" + masterKeyFingerprint +
                '}';
    }

}

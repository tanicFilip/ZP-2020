package etf.openpgp.tf160342dsm160425d.gui;

import java.util.Date;

/**
 * The type Key ring human format.
 */
public class KeyRingHumanFormat {

    /**
     * The enum Key type.
     */
    public enum KeyType {
        /**
         * Secret key type.
         */
        SECRET,
        /**
         * Public key type.
         */
        PUBLIC,
        /**
         * Pair key type.
         */
        PAIR
    }

    private String name;
    private String email;
    private Date dateCreated;
    private Date dateExpires;
    private String masterKeyFingerprint;
    private KeyType keyType;

    /**
     * Instantiates a new Key ring human format.
     */
    public KeyRingHumanFormat() {
    }

    /**
     * Instantiates a new Key ring human format.
     *
     * @param name                 the name
     * @param email                the email
     * @param dateCreated          the date created
     * @param dateExpires          the date expires
     * @param masterKeyFingerprint the master key fingerprint
     */
    public KeyRingHumanFormat(String name, String email, Date dateCreated, Date dateExpires, String masterKeyFingerprint) {
        this.name = name;
        this.email = email;
        this.dateCreated = dateCreated;
        this.dateExpires = dateExpires;
        this.masterKeyFingerprint = masterKeyFingerprint;
    }

    /**
     * Gets name.
     *
     * @return the name
     */
    public String getName() {
        return name;
    }

    /**
     * Sets name.
     *
     * @param name the name
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Gets email.
     *
     * @return the email
     */
    public String getEmail() {
        return email;
    }

    /**
     * Sets email.
     *
     * @param email the email
     */
    public void setEmail(String email) {
        this.email = email;
    }

    /**
     * Gets date created.
     *
     * @return the date created
     */
    public Date getDateCreated() {
        return dateCreated;
    }

    /**
     * Sets date created.
     *
     * @param dateCreated the date created
     */
    public void setDateCreated(Date dateCreated) {
        this.dateCreated = dateCreated;
    }

    /**
     * Gets date expires.
     *
     * @return the date expires
     */
    public Date getDateExpires() {
        return dateExpires;
    }

    /**
     * Sets date expires.
     *
     * @param dateExpires the date expires
     */
    public void setDateExpires(Date dateExpires) {
        this.dateExpires = dateExpires;
    }

    /**
     * Gets master key fingerprint.
     *
     * @return the master key fingerprint
     */
    public String getMasterKeyFingerprint() {
        return masterKeyFingerprint;
    }

    /**
     * Sets master key fingerprint.
     *
     * @param masterKeyFingerprint the master key fingerprint
     */
    public void setMasterKeyFingerprint(String masterKeyFingerprint) {
        this.masterKeyFingerprint = masterKeyFingerprint;
    }

    /**
     * Gets key type.
     *
     * @return the key type
     */
    public KeyType getKeyType() {
        return keyType;
    }

    /**
     * Sets key type.
     *
     * @param keyType the key type
     */
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

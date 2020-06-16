package etf.openpgp.tf160342dsm160425d.backend.openpgp.pgp;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

/**
 * The interface Key ring manager.
 */
public interface KeyRingManager {
    // reading key rings (collections)

    /**
     * Read secret key ring collection pgp secret key ring collection.
     *
     * @return the pgp secret key ring collection
     * @throws IOException  the io exception
     * @throws PGPException the pgp exception
     */
    PGPSecretKeyRingCollection readSecretKeyRingCollection() throws IOException, PGPException;

    /**
     * Read public key ring collection pgp public key ring collection.
     *
     * @return the pgp public key ring collection
     * @throws IOException  the io exception
     * @throws PGPException the pgp exception
     */
    PGPPublicKeyRingCollection readPublicKeyRingCollection() throws IOException, PGPException;

    // importing keys (rings)

    /**
     * Import public key.
     *
     * @param publicKeyFilename the public key filename
     * @throws IOException  the io exception
     * @throws PGPException the pgp exception
     */
    void importPublicKey(String publicKeyFilename) throws IOException, PGPException;

    /**
     * Import secret key.
     *
     * @param secretKeyFilename the secret key filename
     * @throws IOException  the io exception
     * @throws PGPException the pgp exception
     */
    void importSecretKey(String secretKeyFilename) throws IOException, PGPException;

    // Adding keys to the keyring

    /**
     * Add el gamal key pair to key rings.
     *
     * @param userId         the user id
     * @param password       the password
     * @param elGamalKeyRing the el gamal key ring
     * @throws PGPException             the pgp exception
     * @throws IOException              the io exception
     * @throws NoSuchAlgorithmException the no such algorithm exception
     */
    void addElGamalKeyPairToKeyRings(String userId, String password, PGPKeyPair elGamalKeyRing) throws PGPException, IOException, NoSuchAlgorithmException;

    /**
     * Add master key pair to key rings.
     *
     * @param userId   the user id
     * @param password the password
     * @param keyPair  the key pair
     * @throws PGPException the pgp exception
     * @throws IOException  the io exception
     */
    void addMasterKeyPairToKeyRings(String userId, String password, PGPKeyPair keyPair) throws PGPException, IOException;

    /**
     * Adds a new complete KeyRing to KeyRings
     *
     * @param userId    the user id
     * @param password  the password
     * @param masterKey the master key pair (DSA)
     * @param subKey    the sub key pair (ElGamal)
     * @throws PGPException the pgp exception
     * @throws IOException  the io exception
     */
    public void addMasterAndSubKeyPairsToKeyRings(String userId, String password, PGPKeyPair masterKey, PGPKeyPair subKey) throws PGPException, IOException;

    /**
     * Remove key ring from secret key ring collection.
     *
     * @param userId                     the user id
     * @param password                   the password
     * @param masterPublicKeyFingerprint the master public key fingerprint
     * @throws IOException  the io exception
     * @throws PGPException the pgp exception
     */
    void removeKeyRingFromSecretKeyRingCollection(
            String userId, String password, byte[] masterPublicKeyFingerprint
    ) throws IOException, PGPException;

    /**
     * Remove key ring from public key ring collection.
     *
     * @param userId                     the user id
     */
    void removeKeyRingFromPublicKeyRingCollection(String userId);
}

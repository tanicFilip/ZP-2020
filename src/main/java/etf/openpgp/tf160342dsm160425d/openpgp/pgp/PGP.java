package etf.openpgp.tf160342dsm160425d.openpgp.pgp;

import etf.openpgp.tf160342dsm160425d.openpgp.exceptions.IncorrectPasswordException;
import etf.openpgp.tf160342dsm160425d.openpgp.exceptions.PublicKeyRingDoesNotContainElGamalKey;
import org.bouncycastle.openpgp.*;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

/**
 * The interface Pgp.
 */
public interface PGP {

    /**
     * Generate key pair pgp key pair.
     *
     * @param algorithm    the algorithm
     * @param algorithmTag the algorithm tag
     * @param keySize      the key size
     * @return the pgp key pair
     * @throws NoSuchAlgorithmException the no such algorithm exception
     * @throws PGPException             the pgp exception
     */
// generates key pair
    PGPKeyPair generateKeyPair(String algorithm, int algorithmTag, int keySize) throws NoSuchAlgorithmException, PGPException;

    /**
     * Sign message byte [ ].
     *
     * @param data             the data
     * @param password         the password
     * @param pgpSecretKeyRing the pgp secret key ring
     * @return the byte [ ]
     * @throws PGPException the pgp exception
     * @throws IOException  the io exception
     */
// signing and reading signed message
    byte[] signMessage(byte[] data, String password, PGPSecretKeyRing pgpSecretKeyRing) throws PGPException, IOException;

    /**
     * Read signed message byte [ ].
     *
     * @param signedMessage the signed message
     * @param publicKey     the public key
     * @return the byte [ ]
     * @throws Exception the exception
     */
    byte[] readSignedMessage(byte[] signedMessage, PGPPublicKey publicKey) throws Exception;

    /**
     * Encrypt message.
     *
     * @param sourceFileName    the source file name
     * @param encryptedFileName the encrypted file name
     * @param shouldZIP         the should zip
     * @param shouldRadix       the should radix
     * @param algorithmTag      the algorithm tag
     * @param receiverPublicKey the receiver public key
     * @throws IOException                           the io exception
     * @throws PGPException                          the pgp exception
     * @throws PublicKeyRingDoesNotContainElGamalKey the public key ring does not contain el gamal key
     */
// encrypting message
    void encryptMessage(String sourceFileName, String encryptedFileName, boolean shouldZIP, boolean shouldRadix, int algorithmTag, List<PGPKeyRing> receiverPublicKey)
            throws IOException, PGPException, PublicKeyRingDoesNotContainElGamalKey;

    /**
     * Verify message byte [ ].
     *
     * @param inputFileName                    the input file name
     * @param receiversPublicKeyRingCollection the receivers public key ring collection
     * @return the byte [ ]
     */
// decryption
    byte[] verifyMessage(String inputFileName, PGPPublicKeyRingCollection receiversPublicKeyRingCollection);

    /**
     * Verify message byte [ ] [ ].
     *
     * @param inputFileName  the input file name
     * @param keyRingManager the key ring manager
     * @return the byte [ ] [ ]
     * @throws IOException  the io exception
     * @throws PGPException the pgp exception
     */
    byte[][] verifyMessage(String inputFileName, KeyRingManager keyRingManager) throws IOException, PGPException;

    /**
     * Decrypt file.
     *
     * @param inputFileName           the input file name
     * @param outputFileName          the output file name
     * @param password                the password
     * @param secretKeyRingCollection the secret key ring collection
     * @throws IncorrectPasswordException the incorrect password exception
     */
    void decryptFile(String inputFileName, String outputFileName, String password, PGPSecretKeyRingCollection secretKeyRingCollection) throws IncorrectPasswordException;

}

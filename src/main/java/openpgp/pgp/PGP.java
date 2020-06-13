package openpgp.pgp;

import openpgp.exceptions.BadMessageException;
import openpgp.exceptions.PublicKeyRingDoesNotContainElGamalKey;
import org.bouncycastle.openpgp.*;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public interface PGP {

    // generates key pair
    PGPKeyPair generateKeyPair(String algorithm, int algorithmTag, int keySize) throws NoSuchAlgorithmException, PGPException;

    // signing and reading signed message
    byte[] signMessage(byte[] data, PGPKeyPair pgpKeyPair) throws PGPException, IOException;
    byte[] readSignedMessage(byte[] signedMessage, PGPPublicKey publicKey) throws Exception;

    // encrypting message
    void encryptMessage(String sourceFileName, String encryptedFileName, boolean shouldZIP, PGPPublicKeyRing receiverPublicKey)
            throws IOException, PGPException, PublicKeyRingDoesNotContainElGamalKey;


    void readEncryptedFile(String outputFileName, String receivedFileName, PGPPrivateKey pgpPrivateKey)
            throws IOException, PGPException, BadMessageException;
}
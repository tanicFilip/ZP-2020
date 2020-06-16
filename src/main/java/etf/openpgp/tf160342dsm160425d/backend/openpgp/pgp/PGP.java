package etf.openpgp.tf160342dsm160425d.backend.openpgp.pgp;

import etf.openpgp.tf160342dsm160425d.backend.openpgp.exceptions.PublicKeyRingDoesNotContainElGamalKey;
import org.bouncycastle.openpgp.*;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

public interface PGP {

    // generates key pair
    PGPKeyPair generateKeyPair(String algorithm, int algorithmTag, int keySize) throws NoSuchAlgorithmException, PGPException;

    // signing and reading signed message
    byte[] signMessage(byte[] data, String password, PGPSecretKeyRing pgpSecretKeyRing) throws PGPException, IOException;
    byte[] readSignedMessage(byte[] signedMessage, PGPPublicKey publicKey) throws Exception;

    // encrypting message
    void encryptMessage(String sourceFileName, String encryptedFileName, boolean shouldZIP, boolean shouldRadix, int algorithmTag, List<PGPKeyRing> receiverPublicKey)
            throws IOException, PGPException, PublicKeyRingDoesNotContainElGamalKey;

    // decryption
    byte[] verifyMessage(String inputFileName, PGPPublicKeyRingCollection receiversPublicKeyRingCollection);
    void decryptFile(String inputFileName, String outputFileName, String password, PGPSecretKeyRingCollection secretKeyRingCollection);

}

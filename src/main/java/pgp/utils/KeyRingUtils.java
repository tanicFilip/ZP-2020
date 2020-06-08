package pgp.utils;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.bc.BcPGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.bc.BcPGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import pgp.Sender;
import pgp.exceptions.PublicKeyDoesNotExistException;

import java.io.*;

public class KeyRingUtils {

    // parameters provided in the project
    private static int SHA1_ALGORITHM_TAG = HashAlgorithmTags.SHA1;
    private static int SHA384_ALGORITHM_TAG = HashAlgorithmTags.SHA1;
    private static String BC_PROVIDER = "BC";

    public BcPGPSecretKeyRingCollection generateEmptySecretKeyRingCollection() throws IOException, PGPException {
        InputStream inputStream = PGPUtil.getDecoderStream(InputStream.nullInputStream());
        return new BcPGPSecretKeyRingCollection(inputStream);
    }

    public BcPGPPublicKeyRingCollection generatePublicKeyRingCollectionFromFile(String filename) throws IOException, PGPException {
        InputStream inputStream = new FileInputStream(filename);
        return new BcPGPPublicKeyRingCollection(inputStream);
    }

    public PGPSecretKeyRing generateSecretKeyRing(String email, String password, PGPKeyPair pgpKeyPair) throws PGPException, IOException {
        PGPDigestCalculator sha1Calculator =
                new JcaPGPDigestCalculatorProviderBuilder()
                        .build()
                        .get(SHA1_ALGORITHM_TAG);

        PGPContentSignerBuilder pgpContentSignerBuilder =
                new JcaPGPContentSignerBuilder(
                        pgpKeyPair.getPublicKey().getAlgorithm(),
                        SHA384_ALGORITHM_TAG
                );

        PBESecretKeyEncryptor pbeSecretKeyEncryptor =
                new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calculator)
                        .setProvider(BC_PROVIDER)
                        .build(password.toCharArray());

        PGPKeyRingGenerator keyRingGen =
                new PGPKeyRingGenerator(
                        PGPSignature.POSITIVE_CERTIFICATION,
                        pgpKeyPair,
                        email,
                        sha1Calculator,
                        null,
                        null,
                        pgpContentSignerBuilder,
                        pbeSecretKeyEncryptor
                );

        // TODO - mrzi me sad da provaljujem logiku za prosledjivanje public kljuceva, td cu ovde zakucati u file i citati i znjega u receiver-u
        // TODO - OBAVEZNO IZBACITI
        DataWriteUtils.writeBytesToFile(keyRingGen.generatePublicKeyRing().getEncoded(), Sender.receiverKeyringFileName);
        // TODO - kraj
        return keyRingGen.generateSecretKeyRing();
    }


    public PGPSecretKey findSecretKeyByPublicKey(PGPSecretKeyRingCollection secretKeyRingCollection, PGPPublicKey pgpPublicKey)
            throws PublicKeyDoesNotExistException {
        var secretKeyRingIterator = secretKeyRingCollection.getKeyRings();

        while (secretKeyRingIterator.hasNext()){
            var secretKeyRing = secretKeyRingIterator.next();
            if(secretKeyRing.getSecretKey().getPublicKey().getKeyID() == pgpPublicKey.getKeyID()){
                return secretKeyRing.getSecretKey();
            }
        }

        throw new PublicKeyDoesNotExistException();
    }
}

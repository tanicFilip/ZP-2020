package pgp.utils;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.bc.BcPGPPublicKeyRing;
import org.bouncycastle.openpgp.bc.BcPGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.bc.BcPGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pgp.exceptions.BadUserIdFormat;
import pgp.exceptions.PublicKeyDoesNotExistException;

import java.io.*;
import java.time.Instant;
import java.util.Objects;

public class KeyRingUtils {

    private static final Logger logger = LoggerFactory.getLogger(KeyRingUtils.class);

    private PGPSecretKeyRingCollection generateEmptySecretKeyRingCollection() throws IOException, PGPException {
        InputStream inputStream = PGPUtil.getDecoderStream(InputStream.nullInputStream());
        return new BcPGPSecretKeyRingCollection(inputStream);
    }

    private PGPPublicKeyRingCollection generateEmptyPublicKeyRingCollection() throws IOException, PGPException {
        InputStream inputStream = PGPUtil.getDecoderStream(InputStream.nullInputStream());
        return new BcPGPPublicKeyRingCollection(inputStream);
    }

    // Read keyRingCollection from file (if file does not exist return empty collection)
    public PGPSecretKeyRingCollection readSecretKeyRingCollectionFromFile(String filename) throws IOException, PGPException {

        File file = new File(filename);
        if (!file.exists()) {
            return generateEmptySecretKeyRingCollection();
        }
        InputStream inputStream = new FileInputStream(file);
        return new BcPGPSecretKeyRingCollection(inputStream);

    }

    public PGPPublicKeyRingCollection readPublicKeyRingCollectionFromFile(String userId) throws IOException, PGPException {

        File file = new File(generatePublicKeyRingCollectionFileName(userId));
        if (!file.exists()) {
            return generateEmptyPublicKeyRingCollection();
        }
        InputStream inputStream = new FileInputStream(file);
        return new BcPGPPublicKeyRingCollection(inputStream);

    }

    private PGPPublicKeyRing readPublicKeyRingFromFile(String filename) throws IOException {
        InputStream inputStream = new FileInputStream(filename);
        return new BcPGPPublicKeyRing(inputStream);
    }

    // Generates KeyRingPair - adds SecretKeyRing to current users secret key ring file, and creates public key ring file
    public void addKeyPairToKeyRings(String userId, String password, PGPKeyPair pgpKeyPair) throws PGPException, IOException {

        var sha1Calculator = new JcaPGPDigestCalculatorProviderBuilder()
                .build()
                .get(HashAlgorithmTags.SHA1);

        var pgpContentSignerBuilder = new JcaPGPContentSignerBuilder(
                pgpKeyPair.getPublicKey().getAlgorithm(),
                HashAlgorithmTags.SHA384
        );

        var pbeSecretKeyEncryptor =
                new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calculator)
                        .setProvider("BC")
                        .build(password.toCharArray());

        var keyRingGenerator =
                new PGPKeyRingGenerator(
                        PGPSignature.POSITIVE_CERTIFICATION,
                        pgpKeyPair,
                        userId,
                        sha1Calculator,
                        null,
                        null,
                        pgpContentSignerBuilder,
                        pbeSecretKeyEncryptor
                );

        // Generated public key store to a separate file that can later be exchanged between users
        DataWriteUtils.writeBytesToFile(keyRingGenerator.generatePublicKeyRing().getEncoded(), generatePublicKeyRingFileName(userId));

        // Genereate secret key, add it to current private key ring
        var keyRingCollection = readSecretKeyRingCollectionFromFile(generateSecretKeyRingCollectionFileName(userId));
        var secretKeyRing = keyRingGenerator.generateSecretKeyRing();
        keyRingCollection = PGPSecretKeyRingCollection.addSecretKeyRing(keyRingCollection, secretKeyRing);
        DataWriteUtils.writeBytesToFile(keyRingCollection.getEncoded(), generateSecretKeyRingCollectionFileName(userId));
    }

    // Adds public key ring from file to users public key ring collection
    public void addPublicKeyToPublicKeyRingCollection(String userId, String publicKeyFileName) throws IOException, PGPException {
        PGPPublicKeyRing publicKey = readPublicKeyRingFromFile(publicKeyFileName);
        PGPPublicKeyRingCollection publicKeyRings = readPublicKeyRingCollectionFromFile(userId);

        try {
            publicKeyRings = PGPPublicKeyRingCollection.addPublicKeyRing(publicKeyRings, publicKey);
        }catch (IllegalArgumentException e){
            logger.error("{} Key is skipped", e.getMessage());
        }

        DataWriteUtils.writeBytesToFile(publicKeyRings.getEncoded(), generatePublicKeyRingCollectionFileName(userId));
    }


    // No idea why i wrote this method
    public PGPSecretKey findSecretKeyByPublicKey(PGPSecretKeyRingCollection secretKeyRingCollection, PGPPublicKey pgpPublicKey)
            throws PublicKeyDoesNotExistException {
        var secretKeyRingIterator = secretKeyRingCollection.getKeyRings();

        while (secretKeyRingIterator.hasNext()) {
            var secretKeyRing = secretKeyRingIterator.next();
            if (secretKeyRing.getSecretKey().getPublicKey().getKeyID() == pgpPublicKey.getKeyID()) {
                return secretKeyRing.getSecretKey();
            }
        }

        throw new PublicKeyDoesNotExistException();
    }

    /**
     * Encodes user's name and email into a single String
     *
     * @param name
     * @param email
     * @return userId String
     */
    private String generateUserId(String name, String email){
        return String.format("%s__%s", name, email);
    }

    /**
     * Decodes user's Id into name and email Strings
     *
     * @param userId
     * @return user's name at [0] and user's email at [1]
     * @throws BadUserIdFormat
     */
    private String[] getUserCredentialsFromId(String userId) throws BadUserIdFormat {
        String[] retVal = userId.split("__");

        if(retVal.length != 2){
            throw new BadUserIdFormat("User id " + userId + " is in incorrect format");
        }

        return retVal;
    }

    private String generatePublicKeyRingFileName(String userId) {
        return String.format("%s_%d.txt", userId, Instant.now().hashCode());
    }

    private String generateSecretKeyRingCollectionFileName(String userId) {
        return String.format("%s-secret-key-ring-collection.txt", userId);
    }

    private String generatePublicKeyRingCollectionFileName(String userId) {
        return String.format("%s-public-key-ring-collection.txt", userId);
    }
}

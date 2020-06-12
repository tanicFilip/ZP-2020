package pgp.utils;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.bc.BcPGPPublicKeyRing;
import org.bouncycastle.openpgp.bc.BcPGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.bc.BcPGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
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

    private String secretKeyRingCollectionFilename;
    private String publicKeyRingCollectionFilename;

    public KeyRingUtils(String secretKeyRingCollectionFilename, String publicKeyRingCollectionFilename) {
        this.secretKeyRingCollectionFilename = secretKeyRingCollectionFilename;
        this.publicKeyRingCollectionFilename = publicKeyRingCollectionFilename;
    }

    public PGPSecretKeyRingCollection generateEmptySecretKeyRingCollection() throws IOException, PGPException {
        InputStream inputStream = PGPUtil.getDecoderStream(InputStream.nullInputStream());
        return new BcPGPSecretKeyRingCollection(inputStream);
    }

    public PGPPublicKeyRingCollection generateEmptyPublicKeyRingCollection() throws IOException, PGPException {
        InputStream inputStream = PGPUtil.getDecoderStream(InputStream.nullInputStream());
        return new BcPGPPublicKeyRingCollection(inputStream);
    }

    // Read keyRingCollection from file (if file does not exist return empty collection)
    public PGPSecretKeyRingCollection readSecretKeyRingCollectionFromFile() throws IOException, PGPException {

        File file = new File(secretKeyRingCollectionFilename);
        if (!file.exists()) {
            return generateEmptySecretKeyRingCollection();
        }
        InputStream inputStream = new FileInputStream(file);
        return new BcPGPSecretKeyRingCollection(inputStream);

    }

    public PGPPublicKeyRingCollection readPublicKeyRingCollectionFromFile() throws IOException, PGPException {

        File file = new File(publicKeyRingCollectionFilename);
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
    public void addKeyPairToKeyRings(
            String userId, String password, PGPKeyPair pgpKeyPairMaster, PGPKeyPair pgpKeyPairSubkey
    ) throws PGPException, IOException {

        var sha1Calculator = new JcaPGPDigestCalculatorProviderBuilder()
                .build()
                .get(HashAlgorithmTags.SHA1);

        var pgpContentSignerBuilder = new JcaPGPContentSignerBuilder(
                pgpKeyPairMaster.getPublicKey().getAlgorithm(),
                HashAlgorithmTags.SHA384
        );

        var pbeSecretKeyEncryptor =
                new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calculator)
                        .setProvider("BC")
                        .build(password.toCharArray());

        var keyRingGenerator =
                new PGPKeyRingGenerator(
                        PGPSignature.POSITIVE_CERTIFICATION,
                        pgpKeyPairMaster,
                        userId,
                        sha1Calculator,
                        null,
                        null,
                        pgpContentSignerBuilder,
                        pbeSecretKeyEncryptor
                );

        // Adding the ElGamal subkey with master being the DSA key
        keyRingGenerator.addSubKey(pgpKeyPairSubkey);

        // Generated public key store to a separate file that can later be exchanged between users
        //DataWriteUtils.writeBytesToFile(keyRingGenerator.generatePublicKeyRing().getEncoded(), generatePublicKeyRingFileName(userId));

        // Generate secret key, add it to current private key ring
        var keyRingCollection = readSecretKeyRingCollectionFromFile();
        var secretKeyRing = keyRingGenerator.generateSecretKeyRing();
        keyRingCollection = PGPSecretKeyRingCollection.addSecretKeyRing(keyRingCollection, secretKeyRing);
        DataWriteUtils.writeBytesToFile(keyRingCollection.getEncoded(), secretKeyRingCollectionFilename);
    }


    public void removeKeyRingFromSecretKeyRingCollection(
            String userId, String password, byte[] masterPublicKeyFingerprint
    ) throws IOException, PGPException {
        var secretKeyRingCollection = readSecretKeyRingCollectionFromFile();
        var iterator = secretKeyRingCollection.getKeyRings();

        var sha1CalculatorProvider = new JcaPGPDigestCalculatorProviderBuilder()
                .build();

        var pbeSecretKeyDecryptor =  new JcePBESecretKeyDecryptorBuilder(sha1CalculatorProvider)
                .setProvider("BC")
                .build(password.toCharArray());

        boolean found = false;
        PGPSecretKeyRing target = null;

        while(iterator.hasNext()){
            var keyRing = iterator.next();

            try {
                if(keyRing.getPublicKey().getUserIDs().next().equals(userId)){
                    boolean matchingFingerprint = true;
                    for (int i = 0; i < masterPublicKeyFingerprint.length; i++) {
                        if(keyRing.getPublicKey().getFingerprint()[i] != masterPublicKeyFingerprint[i]){
                            matchingFingerprint = false;
                            break;
                        }
                    }
                    if(matchingFingerprint){
                        keyRing.getSecretKey().extractPrivateKey(pbeSecretKeyDecryptor);
                        target = keyRing;
                        break;
                    }
                }

            } catch (Exception e) {
                //throw new PGPException("No private key available using passphrase", e);
            }
        }
        if(target != null){
            secretKeyRingCollection = PGPSecretKeyRingCollection.removeSecretKeyRing(secretKeyRingCollection, target);
            DataWriteUtils.writeBytesToFile(secretKeyRingCollection.getEncoded(), secretKeyRingCollectionFilename);
        }
        else{
            throw new PGPException("No private key available using passphrase");
        }
    }

    public void removeKeyRingFromPublicKeyRingCollection(String userId){

    }

    // Adds public key ring from file to users public key ring collection
    public void addPublicKeyToPublicKeyRingCollection(String publicKeyFilename) throws IOException, PGPException {
        PGPPublicKeyRing publicKey = readPublicKeyRingFromFile(publicKeyFilename);
        PGPPublicKeyRingCollection publicKeyRings = readPublicKeyRingCollectionFromFile();

        try {
            publicKeyRings = PGPPublicKeyRingCollection.addPublicKeyRing(publicKeyRings, publicKey);
        }catch (IllegalArgumentException e){
            logger.error("{} Key is skipped", e.getMessage());
        }

        DataWriteUtils.writeBytesToFile(publicKeyRings.getEncoded(), publicKeyRingCollectionFilename);
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
    public String generateUserId(String name, String email){
        return String.format("%s__%s", name, email);
    }

    /**
     * Decodes user's Id into name and email Strings
     *
     * @param userId
     * @return user's name at [0] and user's email at [1]
     * @throws BadUserIdFormat
     */
    public String[] getUserCredentialsFromId(String userId) throws BadUserIdFormat {
        String[] retVal = userId.split("__");

        if(retVal.length != 2){
            throw new BadUserIdFormat("User id " + userId + " is in incorrect format");
        }

        return retVal;
    }

    private String generatePublicKeyRingFileName(String userId) {
        return String.format("%s_%d.txt", userId, Instant.now().hashCode());
    }

    @Deprecated
    private String generateSecretKeyRingCollectionFileName(String userId) {
        return String.format("%s-secret-key-ring-collection.txt", userId);
    }

    @Deprecated
    private String generatePublicKeyRingCollectionFileName(String userId) {
        return String.format("%s-public-key-ring-collection.txt", userId);
    }
}

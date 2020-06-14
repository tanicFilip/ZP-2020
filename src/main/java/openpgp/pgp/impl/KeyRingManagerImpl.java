package openpgp.pgp.impl;

import openpgp.pgp.KeyRingManager;
import openpgp.pgp.PGP;
import openpgp.utils.DataWriteUtils;
import openpgp.utils.ConstantAndNamingUtils;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.bc.BcPGPPublicKeyRing;
import org.bouncycastle.openpgp.bc.BcPGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.bc.BcPGPSecretKeyRing;
import org.bouncycastle.openpgp.bc.BcPGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

/**
 * The type Key ring manager.
 */
public class KeyRingManagerImpl implements KeyRingManager {

    private static final Logger logger = LoggerFactory.getLogger(KeyRingManagerImpl.class);

    private String secretKeyRingCollectionFilename;
    private String publicKeyRingCollectionFilename;
    private PGP pgp = new PGPImpl();

    public KeyRingManagerImpl(String secretKeyRingCollectionFilename, String publicKeyRingCollectionFilename) {
        this.secretKeyRingCollectionFilename = secretKeyRingCollectionFilename;
        this.publicKeyRingCollectionFilename = publicKeyRingCollectionFilename;
    }

    // Reading key ring collections
    @Override
    public PGPSecretKeyRingCollection readSecretKeyRingCollection() throws IOException, PGPException {
        return readSecretKeyRingCollection(secretKeyRingCollectionFilename);
    }

    private PGPSecretKeyRingCollection readSecretKeyRingCollection(String filename) throws IOException, PGPException {
        File file = new File(filename);
        if (!file.exists()) {
            return generateEmptySecretKeyRingCollection();
        }
        InputStream inputStream = new FileInputStream(file);
        return new BcPGPSecretKeyRingCollection(inputStream);
    }

    @Override
    public PGPPublicKeyRingCollection readPublicKeyRingCollection() throws IOException, PGPException {
        return readPublicKeyRingCollectionFromFile(publicKeyRingCollectionFilename);
    }

    private PGPPublicKeyRingCollection readPublicKeyRingCollectionFromFile(String fileName) throws IOException, PGPException {
        File file = new File(fileName);
        if (!file.exists()) {
            return generateEmptyPublicKeyRingCollection();
        }
        InputStream inputStream = new FileInputStream(file);
        return new BcPGPPublicKeyRingCollection(inputStream);
    }

    // importing
    @Override
    public void importPublicKey(String publicKeyFilename) throws IOException, PGPException {
        PGPPublicKeyRing publicKey = readPublicKeyRingFromFile(publicKeyFilename);
        PGPPublicKeyRingCollection publicKeyRings = readPublicKeyRingCollection();

        try {
            publicKeyRings = PGPPublicKeyRingCollection.addPublicKeyRing(publicKeyRings, publicKey);
        }catch (IllegalArgumentException e){
            logger.error("{} Key is skipped!", e.getMessage());
        }

        DataWriteUtils.writeBytesToFile(publicKeyRings.getEncoded(), publicKeyRingCollectionFilename);
    }

    @Override
    public void importSecretKey(String secretKeyFilename) throws IOException, PGPException {
        PGPSecretKeyRing secretKey = readSecretKeyRingFromFile(secretKeyFilename);
        PGPSecretKeyRingCollection secretKeyRings = readSecretKeyRingCollection();


        try {
            secretKeyRings = PGPSecretKeyRingCollection.addSecretKeyRing(secretKeyRings, secretKey);
        }catch (IllegalArgumentException e){
            logger.error("{} Key is skipped!", e.getMessage());
        }

        DataWriteUtils.writeBytesToFile(secretKeyRings.getEncoded(), secretKeyRingCollectionFilename);
    }

    // import keys helper methods
    private PGPPublicKeyRing readPublicKeyRingFromFile(String filename) throws IOException {
        InputStream inputStream = new FileInputStream(filename);
        return new BcPGPPublicKeyRing(inputStream);
    }

    private PGPSecretKeyRing readSecretKeyRingFromFile(String filename) throws IOException, PGPException {
        InputStream inputStream = new FileInputStream(filename);
        return new BcPGPSecretKeyRing(inputStream);
    }
    // end

    // adding keys to key rings
    @Override
    public void addElGamalKeyPairToKeyRings(String userId, String password, PGPKeyPair elGamalKeyPair) throws PGPException, IOException, NoSuchAlgorithmException {
        PGPKeyPair dummyMasterKeyPair = pgp.generateKeyPair("DSA", PublicKeyAlgorithmTags.DSA, 2048);
        addMasterAndSubKeyPairsToKeyRings(userId, password, dummyMasterKeyPair, elGamalKeyPair);
    }

    @Override
    public void addMasterKeyPairToKeyRings(String userId, String password, PGPKeyPair keyPair) throws PGPException, IOException {
        addMasterAndSubKeyPairsToKeyRings(userId, password, keyPair, null);
    }

    private void addMasterAndSubKeyPairsToKeyRings(String userId, String password, PGPKeyPair masterKey, PGPKeyPair subKey) throws PGPException, IOException {
        PGPKeyRingGenerator keyRingGenerator = getPgpKeyRingGenerator(userId, password, masterKey);
        if(Objects.nonNull(subKey))
            keyRingGenerator.addSubKey(subKey);

        // Generated public key store to a separate file that can later be exchanged between users
        var publicKeyRing = keyRingGenerator.generatePublicKeyRing();

        // generate public key for export
        DataWriteUtils.writeBytesToFile(publicKeyRing.getEncoded(), ConstantAndNamingUtils.generatePublicKeyFileName(userId));

        // Generate secret key, add it to current private key ring
        addSecretKeyRingToTheCollection(keyRingGenerator);
    }

    // adding keys to keyring helper methods
    private PGPKeyRingGenerator getPgpKeyRingGenerator(String userId, String password, PGPKeyPair pgpKeyPairMaster) throws PGPException {
        var sha1Calculator = new JcaPGPDigestCalculatorProviderBuilder()
                .build()
                .get(HashAlgorithmTags.SHA1);

        var pgpContentSignerBuilder = new JcaPGPContentSignerBuilder(
                pgpKeyPairMaster.getPublicKey().getAlgorithm(),
                HashAlgorithmTags.SHA256
        );

        var pbeSecretKeyEncryptor =
                new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calculator)
                        .setProvider("BC")
                        .build(password.toCharArray());

        return new PGPKeyRingGenerator(
                PGPSignature.POSITIVE_CERTIFICATION,
                pgpKeyPairMaster,
                userId,
                sha1Calculator,
                null,
                null,
                pgpContentSignerBuilder,
                pbeSecretKeyEncryptor
        );
    }

    private void addSecretKeyRingToTheCollection(PGPKeyRingGenerator keyRingGenerator) throws IOException, PGPException {
        var keyRingCollection = readSecretKeyRingCollection();
        var secretKeyRing = keyRingGenerator.generateSecretKeyRing();
        keyRingCollection = PGPSecretKeyRingCollection.addSecretKeyRing(keyRingCollection, secretKeyRing);
        DataWriteUtils.writeBytesToFile(keyRingCollection.getEncoded(), secretKeyRingCollectionFilename);
    }
    // end

    // key removal
    @Override
    public void removeKeyRingFromSecretKeyRingCollection(
            String userId, String password, byte[] masterPublicKeyFingerprint
    ) throws IOException, PGPException {
        var secretKeyRingCollection = readSecretKeyRingCollection();
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

    @Override
    public void removeKeyRingFromPublicKeyRingCollection(String userId){

    }

    public PGPSecretKeyRingCollection generateEmptySecretKeyRingCollection() throws IOException, PGPException {
        InputStream inputStream = PGPUtil.getDecoderStream(InputStream.nullInputStream());
        return new BcPGPSecretKeyRingCollection(inputStream);
    }

    /**
     * Generate empty public key ring collection pgp public key ring collection.
     *
     * @return the pgp public key ring collection
     * @throws IOException  the io exception
     * @throws PGPException the pgp exception
     */
    public PGPPublicKeyRingCollection generateEmptyPublicKeyRingCollection() throws IOException, PGPException {
        InputStream inputStream = PGPUtil.getDecoderStream(InputStream.nullInputStream());
        return new BcPGPPublicKeyRingCollection(inputStream);
    }
}

package etf.openpgp.tf160342dsm160425d.backend;

import etf.openpgp.tf160342dsm160425d.backend.gui.KeyRingHumanFormat;
import etf.openpgp.tf160342dsm160425d.backend.gui.SendMessageStage;
import etf.openpgp.tf160342dsm160425d.backend.openpgp.exceptions.PublicKeyRingDoesNotContainElGamalKey;
import etf.openpgp.tf160342dsm160425d.backend.openpgp.pgp.KeyRingManager;
import etf.openpgp.tf160342dsm160425d.backend.openpgp.pgp.PGP;
import etf.openpgp.tf160342dsm160425d.backend.openpgp.pgp.impl.KeyRingManagerImpl;
import etf.openpgp.tf160342dsm160425d.backend.openpgp.pgp.impl.PGPImpl;
import etf.openpgp.tf160342dsm160425d.backend.openpgp.utils.ConstantAndNamingUtils;
import etf.openpgp.tf160342dsm160425d.backend.openpgp.utils.DataWriteUtils;
import org.apache.log4j.BasicConfigurator;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.crypto.tls.EncryptionAlgorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.ArrayList;

public class Backend {

    public static String PUBLIC_KEY_FILES = ".data/export";
    public static String TEMP_FILES = "./data/temp";
    public static String SECRET_FILENAME = "./data/secret_keys_collection.pgp";
    public static String PUBLIC_FILENAME = "./data/public_keys_collection.pgp";

    public static enum ASYMMETRIC {
        DSA , ELGAMAL
    }

    public static int KEY_SIZE_1024 = 1024;
    public static int KEY_SIZE_2048 = 2048;
    public static int KEY_SIZE_4096 = 4096;


    private static Backend instance;

    private PGP pgpImpl = new PGPImpl();
    private KeyRingManager keyRingManagerImpl = new KeyRingManagerImpl(SECRET_FILENAME, PUBLIC_FILENAME);

    private PGPSecretKeyRingCollection secretKeyRingCollection;
    private PGPPublicKeyRingCollection publicKeyRingCollection;

    private Backend(){
        configureLogging();
        initSecurityProvider();
    }

    public static Backend getInstance(){
        if(instance == null){
            instance = new Backend();
        }

        return instance;
    }

    private static void configureLogging(){
        BasicConfigurator.configure();
    }

    private static void initSecurityProvider(){
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Get Secret key ring collection
     *
     * @return null in case of exception
     */
    public PGPSecretKeyRingCollection getSecretKeyRingCollection() {
        try {
            return keyRingManagerImpl.readSecretKeyRingCollection();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Get Public key ring collection
     *
     * @return null in case of exception
     */
    public PGPPublicKeyRingCollection getPublicKeyRingCollection() {
        try {
            return keyRingManagerImpl.readPublicKeyRingCollection();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    private String getStringRepresentation(ASYMMETRIC algorithm){
        switch (algorithm){
            case DSA:
                return "DSA";
            case ELGAMAL:
                return "ELGAMAL";
            default:
                break;
        }

        return "";
    }

    public boolean generateKeyPair(String name, String email, String password, int keySizeDSA, int keySizeELGAMAL){
        try {
            PGPKeyPair keyPairDSA = pgpImpl.generateKeyPair(
                    "DSA",
                    PublicKeyAlgorithmTags.DSA,
                    keySizeDSA
            );

            PGPKeyPair keyPairELGAMAL = pgpImpl.generateKeyPair(
                    "ELGAMAL",
                    PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT,
                    keySizeELGAMAL
            );

            keyRingManagerImpl.addMasterAndSubKeyPairsToKeyRings(
                    ConstantAndNamingUtils.generateUserId(name, email), password, keyPairDSA, keyPairELGAMAL
            );

            return true;

        } catch (NoSuchAlgorithmException | PGPException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return false;
    }

    // TO DO: Detect if key is public or secret and remove accordingly!!!
    public boolean removeKeyPair(String name, String email, String password, byte[] masterPublicKeyFingerprint, KeyRingHumanFormat.KeyType keyType){
        try {
            if(keyType == KeyRingHumanFormat.KeyType.PAIR){
                keyRingManagerImpl.removeKeyRingFromSecretKeyRingCollection(
                        ConstantAndNamingUtils.generateUserId(name, email),
                        password,
                        masterPublicKeyFingerprint
                );
            }
            else if(keyType == KeyRingHumanFormat.KeyType.PUBLIC){
                keyRingManagerImpl.removeKeyRingFromPublicKeyRingCollection(ConstantAndNamingUtils.generateUserId(name, email));
            }

            return true;
        } catch (IOException | PGPException e) {
            e.printStackTrace();
        }

        return false;
    }

    public boolean exportKey(String name, String email, String password, byte[] masterPublicKeyFingerprint, KeyRingHumanFormat.KeyType keyType, KeyRingHumanFormat.KeyType exportKeyType, File exportTo){
        try{
            String userId = ConstantAndNamingUtils.generateUserId(name, email);

            if(keyType == KeyRingHumanFormat.KeyType.PAIR){
                var sha1CalculatorProvider = new JcaPGPDigestCalculatorProviderBuilder()
                        .build();

                var pbeSecretKeyDecryptor =  new JcePBESecretKeyDecryptorBuilder(sha1CalculatorProvider)
                        .setProvider("BC")
                        .build(password.toCharArray());

                var iterator = keyRingManagerImpl.readSecretKeyRingCollection().getKeyRings();
                while(iterator.hasNext()){
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
                                    if(exportKeyType == KeyRingHumanFormat.KeyType.PAIR){
                                        /**
                                         * Will throw an exception in case of wrong password
                                         */
                                        keyRing.getSecretKey().extractPrivateKey(pbeSecretKeyDecryptor);
                                    }

                                    target = keyRing;
                                    break;
                                }
                            }

                        } catch (Exception e) {
                            //throw new PGPException("No private key available using passphrase", e);
                        }
                    }
                    if(target != null){
                        if(exportKeyType == KeyRingHumanFormat.KeyType.PAIR){
                            DataWriteUtils.writeBytesToFile(target.getEncoded(), exportTo.getAbsolutePath());
                        }
                        else if(exportKeyType == KeyRingHumanFormat.KeyType.PUBLIC){
                            Files.copy(
                                    Path.of(ConstantAndNamingUtils.generatePublicKeyFileName(userId, target.getPublicKey().getFingerprint())),
                                    Path.of(exportTo.getAbsolutePath())
                            );
                        }

                        return true;
                    }
                    else{
                        throw new PGPException("No private key available using passphrase");
                    }
                }
            }

            else if(keyType == KeyRingHumanFormat.KeyType.PUBLIC){
                var iterator = keyRingManagerImpl.readPublicKeyRingCollection().getKeyRings();
                while(iterator.hasNext()){
                    boolean found = false;
                    PGPPublicKeyRing target = null;

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
                                    target = keyRing;
                                    break;
                                }
                            }

                        } catch (Exception e) {
                            //throw new PGPException("No key available using passphrase", e);
                        }
                    }
                    if(target != null){
                        DataWriteUtils.writeBytesToFile(target.getEncoded(), exportTo.getAbsolutePath());
                    }
                    else{
                        throw new PGPException("No key available using passphrase");
                    }
                }
            }
        } catch (PGPException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return false;
    }

    public boolean importKey(File importFrom){
        try {
            keyRingManagerImpl.importPublicKey(importFrom.getAbsolutePath());

            return true;
        } catch (IOException e) {
            e.printStackTrace();
        } catch (PGPException e) {
            e.printStackTrace();
        }

        try {
            keyRingManagerImpl.importSecretKey(importFrom.getAbsolutePath());

            return true;
        } catch (IOException e) {
            e.printStackTrace();
        } catch (PGPException e) {
            e.printStackTrace();
        }

        return false;
    }

    public boolean sendMessage(
            File message,
            byte[] privateFingerprint,
            byte[][] publicFingerPrints,
            String password,
            boolean encrypt,
            SendMessageStage.ENCRYPTION_ALGORITHM algorithm,
            boolean sign,
            boolean useZip,
            boolean convertToRadix64
    ){
        ArrayList<String> filesToDelete = new ArrayList<>();
        try {
            String newMessageFilename = message.getAbsolutePath() + ".pgp";
            String currentFile = message.getAbsolutePath();
            String nextFile = null;

            if(sign){
                nextFile = TEMP_FILES + "/_signed";
                filesToDelete.add(nextFile);

                PGPSecretKeyRing matchedKeyRing = null;
                for(PGPSecretKeyRing secretKeyRing : keyRingManagerImpl.readSecretKeyRingCollection()){
                    boolean match = true;
                    var currentFingerprint = secretKeyRing.getPublicKey().getFingerprint();
                    int i = 0;
                    for(; i < currentFingerprint.length && i < privateFingerprint.length; ++i){
                        if(privateFingerprint[i] != currentFingerprint[i]){
                            match = false;
                            break;
                        }
                    }
                    if(match == true && i == currentFingerprint.length && i == privateFingerprint.length){
                        matchedKeyRing = secretKeyRing;
                        break;
                    }
                }

                if(matchedKeyRing == null){
                    throw new PGPException("No such secret key"); // should it ever happen?
                }

                //Find a way to get the required PGPKeyPair from matchedKeyRing(PGPSecretKeyRing)???
                byte[] signedMessage = null;//pgpImpl.signMessage(DataReadUtils.readBytesFromFile(currentFile));
                DataWriteUtils.writeBytesToFile(signedMessage, nextFile);

                currentFile = nextFile;
            }

            if(encrypt){
                nextFile = TEMP_FILES + "_encrypted";
                filesToDelete.add(nextFile);

                int algorithmTag = 0;
                if(algorithm == SendMessageStage.ENCRYPTION_ALGORITHM.ALGO_3DES){
                    algorithmTag = EncryptionAlgorithm._3DES_EDE_CBC;// correct tag?
                }
                else if(algorithm == SendMessageStage.ENCRYPTION_ALGORITHM.ALGO_AES){
                    algorithmTag = EncryptionAlgorithm.AES_128_CBC;// correct tag?
                }

                ArrayList<PGPKeyRing> publicKeyRingsThatMatch = new ArrayList<>();
                ArrayList<PGPKeyRing> allKeys = new ArrayList<>();
                var iterPrivate = keyRingManagerImpl.readSecretKeyRingCollection().getKeyRings();
                while(iterPrivate.hasNext()){
                    allKeys.add(iterPrivate.next());
                }
                var iterPublic = keyRingManagerImpl.readPublicKeyRingCollection().getKeyRings();
                while(iterPublic.hasNext()){
                    allKeys.add(iterPublic.next());
                }

                for(byte[] fingerprint : publicFingerPrints){
                    for(var keyRing : allKeys){
                        boolean match = true;
                        var currentFingerprint = keyRing.getPublicKey().getFingerprint();
                        int i = 0;
                        for(; i < currentFingerprint.length && i < fingerprint.length; ++i){
                            if(fingerprint[i] != currentFingerprint[i]){
                                match = false;
                                break;
                            }
                        }
                        if(match == true && i == currentFingerprint.length && i == fingerprint.length){
                            publicKeyRingsThatMatch.add(keyRing);
                        }
                    }
                }

                pgpImpl.encryptMessage(
                        currentFile,
                        nextFile,
                        useZip,
                        convertToRadix64,
                        algorithmTag,
                        publicKeyRingsThatMatch
                );

                currentFile = nextFile;
            }

            Files.copy(Path.of(currentFile), Path.of(newMessageFilename));

            return true;
        } catch (IOException e) {
            e.printStackTrace();
        } catch (PGPException e) {
            e.printStackTrace();
        } catch (PublicKeyRingDoesNotContainElGamalKey publicKeyRingDoesNotContainElGamalKey) {
            publicKeyRingDoesNotContainElGamalKey.printStackTrace();
        }

        return false;
    }



    public void cleanTempFiles(){
        var tempFolder = new File(TEMP_FILES);
        if(tempFolder.exists() == false){
            tempFolder.mkdir();
        }
        var tempFiles = tempFolder.listFiles();

        for(File tempFile : tempFiles){
            try {
                Files.delete(tempFile.toPath());
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) {
        /*new PGPKeyRingGenerator()

        new PGPPublicKey();*/
    }


}

package backend;

import gui.KeyRingHumanFormat;
import openpgp.pgp.KeyRingManager;
import openpgp.pgp.PGP;
import openpgp.pgp.impl.KeyRingManagerImpl;
import openpgp.pgp.impl.PGPImpl;
import openpgp.utils.ConstantAndNamingUtils;
import openpgp.utils.DataWriteUtils;
import org.apache.log4j.BasicConfigurator;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import java.io.File;
import java.io.FileFilter;
import java.io.FilenameFilter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.regex.Pattern;

public class Backend {

    public static String PUBLIC_KEY_FILES = ".data/export";
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


    public static void main(String[] args) {
        /*new PGPKeyRingGenerator()

        new PGPPublicKey();*/
    }


}

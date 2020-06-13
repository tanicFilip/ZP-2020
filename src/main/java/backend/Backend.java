package backend;

import openpgp.pgp.KeyRingManager;
import openpgp.pgp.PGP;
import openpgp.pgp.impl.KeyRingManagerImpl;
import openpgp.pgp.impl.PGPImpl;
import openpgp.utils.ConstantAndNamingUtils;
import org.apache.log4j.BasicConfigurator;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.bouncycastle.openpgp.*;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

public class Backend {

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

            //keyRingUtils.addKeyPairToKeyRings(keyRingUtils.generateUserId(name, email), password, keyPairDSA, keyPairELGAMAL);

            return true;

        } catch (NoSuchAlgorithmException | PGPException e) {
            e.printStackTrace();
        }
//        } catch (IOException e) {
//            e.printStackTrace();
//        }

        return false;
    }

    // TO DO: Detect if key is public or secret and remove accordingly!!!
    public boolean removeKeyPair(String name, String email, String password, byte[] masterPublicKeyFingerprint){
        try {
            keyRingManagerImpl.removeKeyRingFromSecretKeyRingCollection(
                    ConstantAndNamingUtils.generateUserId(name, email),
                    password,
                    masterPublicKeyFingerprint
            );

            return true;
        } catch (IOException | PGPException e) {
            e.printStackTrace();
        }

        return false;
    }

    public static void main(String[] args) {
        /*new PGPKeyRingGenerator()

        new PGPPublicKey();*/
    }


}

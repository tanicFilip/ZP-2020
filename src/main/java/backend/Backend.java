package backend;

import org.apache.log4j.BasicConfigurator;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyEncSessionPacket;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import pgp.utils.*;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

public class Backend {

    private static String SECRET_FILENAME = "./data/secret_keys_collection.pgp";
    private static String PUBLIC_FILENAME = "./data/public_keys_collection.pgp";

    public static enum ASYMMETRIC {
        DSA , ELGAMAL
    }

    public static int KEY_SIZE_1024 = 1024;
    public static int KEY_SIZE_2048 = 2048;
    public static int KEY_SIZE_4096 = 4096;


    private static Backend instance;

    private PGPUtils pgpUtils = new PGPUtils();
    private KeyRingUtils keyRingUtils = new KeyRingUtils(SECRET_FILENAME, PUBLIC_FILENAME);

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
            return keyRingUtils.readSecretKeyRingCollectionFromFile();
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
            return keyRingUtils.readPublicKeyRingCollectionFromFile();
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
            PGPKeyPair keyPairDSA = pgpUtils.generateKeyPair(
                    "DSA",
                    PublicKeyAlgorithmTags.DSA,
                    keySizeDSA
            );

            PGPKeyPair keyPairELGAMAL = pgpUtils.generateKeyPair(
                    "ELGAMAL",
                    PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT,
                    keySizeELGAMAL
            );

            keyRingUtils.addKeyPairToKeyRings(keyRingUtils.generateUserId(name, email), password, keyPairDSA, keyPairELGAMAL);

            return true;

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (PGPException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return false;
    }

    public void removeKeyPair(){

    }

    public static void main(String[] args) {
        /*new PGPKeyRingGenerator()

        new PGPPublicKey();*/
    }


}

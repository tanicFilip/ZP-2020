package etf.openpgp.tf160342dsm160425d.backend.openpgp;

import etf.openpgp.tf160342dsm160425d.backend.openpgp.pgp.KeyRingManager;
import etf.openpgp.tf160342dsm160425d.backend.openpgp.pgp.PGP;
import etf.openpgp.tf160342dsm160425d.backend.openpgp.pgp.impl.KeyRingManagerImpl;
import etf.openpgp.tf160342dsm160425d.backend.openpgp.pgp.impl.PGPImpl;
import org.apache.log4j.BasicConfigurator;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import etf.openpgp.tf160342dsm160425d.backend.openpgp.exceptions.PublicKeyRingDoesNotContainElGamalKey;
import etf.openpgp.tf160342dsm160425d.backend.openpgp.utils.*;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * The type Sender.
 */
public class Sender {

    private static final Logger logger = LoggerFactory.getLogger(Sender.class);
    private static final String email = "marko@marko.com";
    /**
     * The constant password.
     */
    public static final String password = "password";


    /**
     * The constant senderKeyringFileName.
     */
    public static final String senderKeyringFileName = "sender-keyring.gpg";
    /**
     * The constant receiverKeyringFileName.
     */
    public static final String receiverKeyringFileName = "receiver-keyring.gpg";
    /**
     * The constant inputFileName.
     */
    public static final String inputFileName = "input.txt";
    /**
     * The constant outputFileName.
     */
    public static final String outputFileName = "signed-input.asc";
    /**
     * The constant encodedOutputFileName.
     */
    public static final String encodedOutputFileName = "encoded-input.asc";

    /**
     * The constant DSA.
     */
    public static final String DSA = "DSA";
    /**
     * The constant keySize.
     */
    public static final int keySize = 1024;

    /**
     * The constant pgp.
     */
    public static PGP pgp = new PGPImpl();
    /**
     * The constant senderKeyRingManager.
     */
    public static KeyRingManager senderKeyRingManager = new KeyRingManagerImpl(ConstantAndNamingUtils.SENDER_SECRET_KEY_RING, ConstantAndNamingUtils.SENDER_PUBLIC_KEY_RING);
    /**
     * The constant receiverLeyRingManager.
     */
    public static KeyRingManager receiverLeyRingManager = new KeyRingManagerImpl(ConstantAndNamingUtils.RECEIVER_SECRET_KEY_RING, ConstantAndNamingUtils.RECEIVER_PUBLIC_KEY_RING);


    /**
     * Configure logging.
     */
    public static void configureLogging(){
        BasicConfigurator.configure();
    }

    /**
     * Init security provider.
     */
    public static void initSecurityProvider(){
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * The entry point of application.
     *
     * @param args the input arguments
     * @throws IOException                           the io exception
     * @throws PGPException                          the pgp exception
     * @throws NoSuchAlgorithmException              the no such algorithm exception
     * @throws PublicKeyRingDoesNotContainElGamalKey the public key ring does not contain el gamal key
     */
    public static void main(String[] args) throws IOException, PGPException, NoSuchAlgorithmException, PublicKeyRingDoesNotContainElGamalKey {
        initSecurityProvider();
        configureLogging();


        PGPKeyPair elgamalKeyPair = pgp.generateKeyPair("ELGAMAL", PublicKeyAlgorithmTags.ELGAMAL_GENERAL, keySize);
        long elgamalKeyId = elgamalKeyPair.getKeyID();
        KeyRingManagerImpl receiverKRU = new KeyRingManagerImpl(ConstantAndNamingUtils.RECEIVER_SECRET_KEY_RING, ConstantAndNamingUtils.RECEIVER_PUBLIC_KEY_RING);
        receiverKRU.addElGamalKeyPairToKeyRings("MarkoReceiver", "password", elgamalKeyPair);
        logger.info("Generated receivers elgamal key pair");


        logger.info("Generate new key pair...");
        PGPKeyPair keyPair = pgp.generateKeyPair(DSA, PublicKeyAlgorithmTags.DSA, keySize);
        PGPKeyPair pgpKeyPair = pgp.generateKeyPair(DSA, PublicKeyAlgorithmTags.DSA, keySize);
        logger.info("Generated new key pair.");

        logger.info("Add keypair to keyring collection...");
        senderKeyRingManager.addMasterKeyPairToKeyRings(email, password, keyPair);
        senderKeyRingManager.addMasterKeyPairToKeyRings(email, password, pgpKeyPair);
        logger.info("Saved new keyring collection to file.");

        logger.info("Start reading message from file {}...", inputFileName);
        byte[] message = DataReadUtils.readBytesFromFile(inputFileName);
        logger.info("Read message from {} to byte array.", inputFileName);

        logger.info("Signing the message...");
        // left like this cuz this wont be started, ever
        byte[] signedMessage = pgp.signMessage(message,"password" , null);
        logger.info("Message signed.");

        logger.info("Save signed message to file {}...", outputFileName);
        DataWriteUtils.writeBytesToFile(signedMessage, outputFileName);
        logger.info("Saved signed message to file {}.", outputFileName);

        logger.info("Encrypting message...");
        PGPPublicKeyRingCollection egKeyRingCollection = senderKeyRingManager.readPublicKeyRingCollection();

        //pgp.encryptMessage(outputFileName, encodedOutputFileName, false, egKeyRingCollection.getKeyRings().next());
        logger.info("Message encrypted.");

    }
}

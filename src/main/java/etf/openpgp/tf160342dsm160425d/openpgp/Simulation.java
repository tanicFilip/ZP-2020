package etf.openpgp.tf160342dsm160425d.openpgp;

import etf.openpgp.tf160342dsm160425d.openpgp.exceptions.PublicKeyRingDoesNotContainElGamalKey;
import etf.openpgp.tf160342dsm160425d.openpgp.pgp.KeyRingManager;
import etf.openpgp.tf160342dsm160425d.openpgp.pgp.PGP;
import etf.openpgp.tf160342dsm160425d.openpgp.pgp.impl.KeyRingManagerImpl;
import etf.openpgp.tf160342dsm160425d.openpgp.pgp.impl.PGPImpl;
import etf.openpgp.tf160342dsm160425d.openpgp.utils.ConstantAndNamingUtils;
import etf.openpgp.tf160342dsm160425d.openpgp.utils.DataReadUtils;
import etf.openpgp.tf160342dsm160425d.openpgp.utils.DataWriteUtils;
import org.apache.log4j.BasicConfigurator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * The type Simulation.
 */
public class Simulation {
    private static final Logger logger = LoggerFactory.getLogger(Simulation.class);

    /**
     * The constant SENDER_EMAIL.
     */
    public static final String SENDER_EMAIL = "sender@mail.com";
    /**
     * The constant SENDER_NAME.
     */
    public static final String SENDER_NAME = "Sender";
    /**
     * The constant RECEIVER_EMAIL.
     */
    public static final String RECEIVER_EMAIL = "receiver@mail.com";
    /**
     * The constant RECEIVER_NAME.
     */
    public static final String RECEIVER_NAME = "Receiver";
    /**
     * The constant PASSWORD.
     */
    public static final String PASSWORD = "password";


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
     * The constant decodedSignedFileName.
     */
    public static final String decodedSignedFileName = "decoded-signed-output.asc";
    /**
     * The constant decodedFileName.
     */
    public static final String decodedFileName = "decoded-output.txt";

    /**
     * The constant keySize.
     */
    public static final int keySize = 2048;

    /**
     * The constant pgp.
     */
    public static PGP pgp = new PGPImpl();
    /**
     * The constant senderKeyRingManager.
     */
    public static KeyRingManager senderKeyRingManager = new KeyRingManagerImpl(ConstantAndNamingUtils.SENDER_SECRET_KEY_RING, ConstantAndNamingUtils.SENDER_PUBLIC_KEY_RING);
    /**
     * The constant receiverKeyRingManager.
     */
    public static KeyRingManager receiverKeyRingManager = new KeyRingManagerImpl(ConstantAndNamingUtils.RECEIVER_SECRET_KEY_RING, ConstantAndNamingUtils.RECEIVER_PUBLIC_KEY_RING);

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
     * @throws Exception the exception
     */
    public static void main(String[] args) throws Exception {

        configureLogging();
        initSecurityProvider();

        logger.info("Generating userIds...");
        String receiverId = ConstantAndNamingUtils.generateUserId(RECEIVER_NAME, RECEIVER_EMAIL);
        String senderId = ConstantAndNamingUtils.generateUserId(SENDER_NAME, SENDER_EMAIL );
        logger.info("Generated userIds, sender: {}, receiver: {}", senderId, receiverId);

        // RECEIVER PART
        logger.info("Receiver generates elgamal key");
        PGPKeyPair elgamalKeyPair = null;
        PGPKeyPair elgamalKeyPair1 = null;
        try {
            elgamalKeyPair = pgp.generateKeyPair(ConstantAndNamingUtils.EL_GAMAL_ALGORITHM_NAME, ConstantAndNamingUtils.EL_GAMAL_ALGORITHM_TAG, keySize);
            elgamalKeyPair1 = pgp.generateKeyPair(ConstantAndNamingUtils.EL_GAMAL_ALGORITHM_NAME, ConstantAndNamingUtils.EL_GAMAL_ALGORITHM_TAG, keySize);
        } catch (NoSuchAlgorithmException | PGPException e) {
            logger.error("Failed to generate el gamal key pair");
            return;
        }
        logger.info("Receiver generated elgamal key");

        logger.info("Getting elgamal public key id...");
        long elgamalPublicKeyId = elgamalKeyPair.getPublicKey().getKeyID();
        logger.info("Elgamal public key id: {}", elgamalPublicKeyId);

        logger.info("Receiver adds elgamal key to his private key ring collection...");
        receiverKeyRingManager.addElGamalKeyPairToKeyRings(receiverId, PASSWORD, elgamalKeyPair);
        receiverKeyRingManager.addElGamalKeyPairToKeyRings(receiverId, PASSWORD, elgamalKeyPair1);
        logger.info("Receiver added elgamal key to his private key ring collection.");
        // RECEIVER PART ENDS

        // SENDER PART
        logger.info("Import elgamal public key to senders public key ring..");
        try {
            senderKeyRingManager.importPublicKey(String.format("./data/export/%s-public-key-%s.asc", receiverId, 0));
            senderKeyRingManager.importPublicKey(String.format("./data/export/%s-public-key-%s.asc", receiverId, 1));
        } catch (IOException | PGPException e) {
            logger.error("Failed to import public key. {}", e.getMessage());
            return;
        }
        logger.info("Imported elgamal public key to senders public key ring..");

        logger.info("Sender generates new DSA key pair...");
        PGPKeyPair dsaKeyPair = null;
        try {
            dsaKeyPair = pgp.generateKeyPair(ConstantAndNamingUtils.DSA_ALGORITHM_NAME, ConstantAndNamingUtils.DSA_ALGORITHM_TAG, keySize);
        } catch (NoSuchAlgorithmException | PGPException e) {
            logger.error("Sender failed to generate DSA key pair. {}", e.getMessage());
            return;
        }
        logger.info("Sender generated new key pair.");

        logger.info("Add keypair to keyring collection...");
        try {
            senderKeyRingManager.addMasterKeyPairToKeyRings(senderId, PASSWORD, dsaKeyPair);
        } catch (PGPException | IOException e) {
            logger.error("Failed to add DSA key pair to key ring");
            return;
        }
        logger.info("Saved new keyring collection to file.");

        logger.info("Start reading message from file {}...", inputFileName);
        byte[] message = null;
        try {
            message = DataReadUtils.readBytesFromFile(inputFileName);
        } catch (IOException e) {
            logger.error("Failed to read message");
            return;
        }
        logger.info("Read message from {} to byte array.", inputFileName);

        logger.info("Signing the message...");
        byte[] signedMessage = null;
        try {
            PGPSecretKeyRingCollection dummy = senderKeyRingManager.readSecretKeyRingCollection();
            signedMessage = pgp.signMessage(message, "password" , dummy.iterator().next());
        } catch (PGPException | IOException e) {
            logger.error("Failed to sign message. {}", e.getMessage());
            return;
        }
        logger.info("Message signed.");

        logger.info("Save signed message to file {}...", outputFileName);
        try {
            DataWriteUtils.writeBytesToFile(signedMessage, outputFileName);
        } catch (IOException e) {
            logger.error("Failed to write signed message to file. {}", e.getMessage());
            return;
        }
        logger.info("Saved signed message to file {}.", outputFileName);

        logger.info("Getting public key ring collection...");
        PGPPublicKeyRingCollection senderPublicKeys;
        try {
            senderPublicKeys = senderKeyRingManager.readPublicKeyRingCollection();
        } catch (IOException | PGPException e) {
            e.printStackTrace();
            return;
        }
        logger.info("Retrieved public key ring collection");
        PGPPublicKeyRing elgamalPublicKeyRing = null;
        var iterator = senderPublicKeys.iterator();
        while (iterator.hasNext()){
            var item = iterator.next();
            var itemIterator = item.iterator();
            while (itemIterator.hasNext()){
                logger.info("Finding elgamal");
                var maybeElgamal = itemIterator.next();
                if(maybeElgamal.getKeyID() == elgamalPublicKeyId){
                    logger.info("Found elgamal public key");
                    elgamalPublicKeyRing = item;
                    break;
                }
            }
            if(Objects.nonNull(elgamalPublicKeyRing))
                break;
        }
        if(Objects.isNull(elgamalPublicKeyRing)){
            logger.error("Failed to find elgamal public key");
            return;
        }
        List<PGPKeyRing> elgamalKeys = new ArrayList<>();
        elgamalKeys.add(elgamalPublicKeyRing);
        logger.info("Encrypting message...");
        try {
            pgp.encryptMessage(outputFileName, encodedOutputFileName, true, true, ConstantAndNamingUtils.TRIPLE_DES_ALGORITHM_TAG, elgamalKeys);
        } catch (IOException | PGPException | PublicKeyRingDoesNotContainElGamalKey e) {
            logger.error("Failed to encrypt the message. {}", e.getMessage());
        }
        logger.info("Message encrypted.");
        // SENDER PART ENDS

        // RECEIVER PART BEGINS
        logger.info("Import dsa public key to receivers public key ring..");
        try {
            receiverKeyRingManager.importPublicKey(String.format("./data/export/%s-public-key-%s.asc", senderId, 2));
        } catch (IOException | PGPException e) {
            logger.error("Failed to import public key. {}", e.getMessage());
            return;
        }
        logger.info("Imported dsa public key to receivers public key ring..");

        logger.info("Getting receivers key ring collections...");
        PGPSecretKeyRingCollection receiversSecretKeyRingCollection = null;
        PGPPublicKeyRingCollection receiversPublicKeyRingCollection = null;
        try {
            receiversSecretKeyRingCollection = receiverKeyRingManager.readSecretKeyRingCollection();
            receiversPublicKeyRingCollection = receiverKeyRingManager.readPublicKeyRingCollection();
        } catch (IOException | PGPException e) {
            e.printStackTrace();
            return;
        }
        logger.info("Retrieved recievers key ring collections ");

        // TODO = ovo valja izbacit u zasebnu metodu al me jako mrzi sada
        pgp.decryptFile(encodedOutputFileName, decodedSignedFileName, "password", receiversSecretKeyRingCollection);

        // TODO - a i ovo mozda
        byte[] decodedMessage = pgp.verifyMessage(decodedSignedFileName, receiversPublicKeyRingCollection);

        if(Objects.isNull(decodedMessage))
            throw new Exception("Well this one was unexpected :(");

        String messageString = new String(decodedMessage, Charset.defaultCharset());
        logger.info("Received message: {}", messageString);

        DataWriteUtils.writeBytesToFile(message, decodedFileName);
    }

}

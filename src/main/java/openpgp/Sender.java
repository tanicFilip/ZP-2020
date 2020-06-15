package openpgp;

import openpgp.pgp.KeyRingManager;
import openpgp.pgp.PGP;
import openpgp.pgp.impl.KeyRingManagerImpl;
import openpgp.pgp.impl.PGPImpl;
import org.apache.log4j.BasicConfigurator;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import openpgp.exceptions.PublicKeyRingDoesNotContainElGamalKey;
import openpgp.utils.*;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

public class Sender {

    private static final Logger logger = LoggerFactory.getLogger(Sender.class);
    private static final String email = "marko@marko.com";
    public static final String password = "password";


    public static final String senderKeyringFileName = "sender-keyring.gpg";
    public static final String receiverKeyringFileName = "receiver-keyring.gpg";
    public static final String inputFileName = "input.txt";
    public static final String outputFileName = "signed-input.asc";
    public static final String encodedOutputFileName = "encoded-input.asc";

    public static final String DSA = "DSA";
    public static final int keySize = 1024;

    public static PGP pgp = new PGPImpl();
    public static KeyRingManager senderKeyRingManager = new KeyRingManagerImpl(ConstantAndNamingUtils.SENDER_SECRET_KEY_RING, ConstantAndNamingUtils.SENDER_PUBLIC_KEY_RING);
    public static KeyRingManager receiverLeyRingManager = new KeyRingManagerImpl(ConstantAndNamingUtils.RECEIVER_SECRET_KEY_RING, ConstantAndNamingUtils.RECEIVER_PUBLIC_KEY_RING);


    public static void configureLogging(){
        BasicConfigurator.configure();
    }

    public static void initSecurityProvider(){
        Security.addProvider(new BouncyCastleProvider());
    }

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
        byte[] signedMessage = pgp.signMessage(message, keyPair);
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

package pgp;

import org.apache.log4j.BasicConfigurator;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.bc.BcPGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pgp.utils.DataReadUtils;
import pgp.utils.DataWriteUtils;
import pgp.utils.KeyRingUtils;
import pgp.utils.PGPUtils;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
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

    public static PGPUtils pgpUtils = new PGPUtils();
    public static KeyRingUtils keyRingUtils = new KeyRingUtils();


    public static void configureLogging(){
        BasicConfigurator.configure();
    }

    public static void initSecurityProvider(){
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws IOException, PGPException, NoSuchAlgorithmException {
        initSecurityProvider();
        configureLogging();

        logger.info("Generate new key pair...");
        PGPKeyPair keyPair = pgpUtils.generateKeyPair(DSA, PublicKeyAlgorithmTags.DSA, keySize);
        logger.info("Generated new key pair.");

        logger.info("Add keypair to keyring collection...");
        keyRingUtils.addKeyPairToKeyRings(email, password, keyPair);
        logger.info("Saved new keyring collection to file.");

        logger.info("Start reading message from file {}...", inputFileName);
        byte[] message = DataReadUtils.readBytesFromFile(inputFileName);
        logger.info("Read message from {} to byte array.", inputFileName);

        logger.info("Signing the message...");
        byte[] signedMessage = pgpUtils.signMessage(message, keyPair);
        logger.info("Message signed.");

        logger.info("Save signed message to file {}...", outputFileName);
        DataWriteUtils.writeBytesToFile(signedMessage, outputFileName);
        logger.info("Saved signed message to file {}.", outputFileName);

        logger.info("Encrypting message...");
        pgpUtils.encryptMessage(outputFileName, encodedOutputFileName, password, false);
        logger.info("Message encrypted.");

    }
}

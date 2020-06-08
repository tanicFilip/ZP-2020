package pgp;

import org.apache.log4j.BasicConfigurator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.bc.BcPGPPublicKeyRingCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pgp.utils.DataReadUtils;
import pgp.utils.DataWriteUtils;
import pgp.utils.KeyRingUtils;
import pgp.utils.PGPUtils;


import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.Security;

public class Receiver {

    private static final Logger logger = LoggerFactory.getLogger(Sender.class);

    public static PGPUtils pgpUtils = new PGPUtils();
    public static KeyRingUtils keyRingUtils = new KeyRingUtils();

    public static void configureLogging(){
        BasicConfigurator.configure();
    }

    public static void initSecurityProvider(){
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {

        initSecurityProvider();
        configureLogging();

        logger.info("Getting public keyring collection...");
        BcPGPPublicKeyRingCollection keyRingCollection = keyRingUtils.generatePublicKeyRingCollectionFromFile(Sender.receiverKeyringFileName);
        logger.info("Received public keyring collection.");

        // TODO = trebace da se iterira kada bude vise public keys
        logger.info("Getting public key...");
        PGPPublicKey publicKey = keyRingCollection.getKeyRings().next().getPublicKey();
        logger.info("Found public key.");

//        logger.info("Reading signed message...");
//        byte[] signedMessage  = DataReadUtils.readBytesFromFile(Sender.outputFileName);
//        logger.info("Read signed message");

        logger.info("Reading signed message from zip archive...");
        //byte[] signedMessageZIP = DataReadUtils.readBytesFromZipArchive(Sender.zipFileName);
        logger.info("Read signed message from");

        //logger.info("Verifying signed message...");
        //byte[] message = pgpUtils.readSignedMessage(signedMessageZIP, publicKey);
        //logger.info("Verified signed message");

        InputStream in = new BufferedInputStream(new FileInputStream(Sender.encodedOutputFileName));
        pgpUtils.readEncryptedFile(in);
        in.close();

        String messageString = new String(DataReadUtils.readBytesFromFile("fuck.txt"),Charset.defaultCharset());
        logger.info("Received message: {}", messageString);

        DataWriteUtils.writeBytesToFile(
                pgpUtils.readSignedMessage(DataReadUtils.readBytesFromFile("fuck.txt"), publicKey),
                "ako-ovo-radi.txt"
        );


    }

}

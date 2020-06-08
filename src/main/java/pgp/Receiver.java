package pgp;

import org.apache.log4j.BasicConfigurator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.bc.BcPGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.bc.BcPGPSecretKeyRingCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pgp.utils.DataReadUtils;
import pgp.utils.KeyRingUtils;
import pgp.utils.PGPUtils;

import java.io.IOException;
import java.nio.charset.Charset;
import java.security.PublicKey;
import java.security.Security;
import java.util.List;

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

        logger.info("Reading signed message...");
        byte[] signedMessage  = DataReadUtils.readBytesFromFile(Sender.outputFileName);
        logger.info("Read signed message");

        logger.info("Verifying signed message...");
        byte[] message = pgpUtils.readSignedMessage(signedMessage, publicKey);
        logger.info("Verified signed message");

        String messageString = new String(message, Charset.defaultCharset());
        logger.info("Received message: {}", messageString);


    }

}

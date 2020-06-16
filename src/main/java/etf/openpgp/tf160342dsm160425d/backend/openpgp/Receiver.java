package etf.openpgp.tf160342dsm160425d.backend.openpgp;

import etf.openpgp.tf160342dsm160425d.backend.openpgp.pgp.impl.KeyRingManagerImpl;
import etf.openpgp.tf160342dsm160425d.backend.openpgp.pgp.impl.PGPImpl;
import org.apache.log4j.BasicConfigurator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import etf.openpgp.tf160342dsm160425d.backend.openpgp.utils.*;

import java.security.Security;

/**
 * The type Receiver.
 */
public class Receiver {
    private static final String email = "reciever@mail.com";
    private static final String receivedMessageFileName = "receivedMessage.txt";
    private static final String receivedSignedMessageFileName = "receivedSignedMessage.txt";

    private static final Logger logger = LoggerFactory.getLogger(Sender.class);

    /**
     * The constant pgpImpl.
     */
    public static PGPImpl pgpImpl = new PGPImpl();
    /**
     * The constant keyRingManagerImpl.
     */
    public static KeyRingManagerImpl keyRingManagerImpl = new KeyRingManagerImpl(ConstantAndNamingUtils.RECEIVER_SECRET_KEY_RING, ConstantAndNamingUtils.RECEIVER_PUBLIC_KEY_RING);

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
/*
        initSecurityProvider();
        configureLogging();

        logger.info("Adding public key rings to the collection...");
        KeyRingManagerImpl keyRingManagerImplSender = new KeyRingManagerImpl(ConstantAndNamingUtils.RECEIVER_SECRET_KEY_RING, ConstantAndNamingUtils.RECEIVER_PUBLIC_KEY_RING);
        var publicKeyRingCollection = keyRingManagerImplSender.readPublicKeyRingCollectione();
        logger.info("Read public key rings.");

        logger.info("Getting elgamal private key rings...");
        var elgamalPrivateKeyRingCollection = keyRingManagerImpl.readSecretKeyRingCollection(ConstantAndNamingUtils.RECEIVER_ELGAMAL_SECRET_KEY_RING);
        logger.info("Recieved elgamal private key rings.");

        var elgamalIterator = elgamalPrivateKeyRingCollection.getKeyRings();
        while(elgamalIterator.hasNext()) {

            var elgamalKeyRing = elgamalIterator.next();
            var elgamalKeyRingIterator = elgamalKeyRing.iterator();
            PGPSecretKey secretKey = null;
            while(elgamalKeyRingIterator.hasNext()) {
                secretKey = elgamalKeyRingIterator.next();
                System.err.println(secretKey.getKeyEncryptionAlgorithm());
                if(secretKey.getKeyEncryptionAlgorithm() == PublicKeyAlgorithmTags.ELGAMAL_GENERAL){
                    break;
                }
            }
            if(secretKey == null){
                throw new Exception("No valid secret key");
            }

            logger.info("Decrypting message...");
            try {
                PBESecretKeyDecryptor decryptorFactory = new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build("password".toCharArray());
                pgpImpl.readEncryptedFile(receivedSignedMessageFileName, Sender.encodedOutputFileName, secretKey.extractPrivateKey(decryptorFactory));
                logger.info("Decrypted message.");
            }catch (Exception e){
                logger.info("Wrong key, try again");
            }
        }

        byte[] message = null;
        Iterator<PGPPublicKeyRing> iterator = publicKeyRingCollection.iterator();
        while(iterator.hasNext()){
            PGPPublicKey key = iterator.next().getPublicKey();
            try{
                logger.info("Verifying signed message...");
                message = pgpImpl.readSignedMessage(DataReadUtils.readBytesFromFile(receivedSignedMessageFileName), key);
                logger.info("Verified signed message");
            }catch(InvalidSignatureException e){
                logger.warn("Failed to decrypt the message. Error message: {}", e.getMessage());
            }
        }
        if(Objects.isNull(message))
            throw new Exception("Well this one was unexpected :(");

        String messageString = new String(message,Charset.defaultCharset());
        logger.info("Received message: {}", messageString);

        DataWriteUtils.writeBytesToFile(message, receivedMessageFileName);
        */
    }

}

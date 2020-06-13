package openpgp;

import openpgp.pgp.impl.KeyRingManagerImpl;
import openpgp.pgp.impl.PGPImpl;
import org.apache.log4j.BasicConfigurator;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import openpgp.exceptions.InvalidSignatureException;
import openpgp.utils.*;

import java.nio.charset.Charset;
import java.security.Security;
import java.util.Iterator;
import java.util.Objects;

public class Receiver {
    private static final String email = "reciever@mail.com";
    private static final String receivedMessageFileName = "receivedMessage.txt";
    private static final String receivedSignedMessageFileName = "receivedSignedMessage.txt";

    private static final Logger logger = LoggerFactory.getLogger(Sender.class);

    public static PGPImpl pgpImpl = new PGPImpl();
    public static KeyRingManagerImpl keyRingManagerImpl = new KeyRingManagerImpl(ConstantAndNamingUtils.RECEIVER_SECRET_KEY_RING, ConstantAndNamingUtils.RECEIVER_PUBLIC_KEY_RING);

    public static void configureLogging(){
        BasicConfigurator.configure();
    }

    public static void initSecurityProvider(){
        Security.addProvider(new BouncyCastleProvider());
    }

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

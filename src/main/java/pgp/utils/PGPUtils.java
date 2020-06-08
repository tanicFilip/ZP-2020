package pgp.utils;

import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Date;

public class PGPUtils {

    private static final Logger logger = LoggerFactory.getLogger(PGPUtils.class);
    public static final String BC_PROVIDER = "BC";

    public byte[] signMessage(byte[] data, PGPKeyPair pgpKeyPair) throws PGPException, IOException {
        // Byte out stream - will contain signed data
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        // Create a stream for writing a signature to.
        BCPGOutputStream bcpgOutputStream = new BCPGOutputStream(byteArrayOutputStream);

        JcaPGPContentSignerBuilder jcaPGPContentSignerBuilder = getJcaPGPContentSignerBuilder();


        PGPSignatureGenerator pgpSignatureGenerator = new PGPSignatureGenerator(jcaPGPContentSignerBuilder);
        pgpSignatureGenerator.init(PGPSignature.BINARY_DOCUMENT, pgpKeyPair.getPrivateKey());

        pgpSignatureGenerator
                .generateOnePassVersion(false)
                .encode(bcpgOutputStream);

        PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();

        //
        OutputStream literalOutputStream = literalDataGenerator.open(
                bcpgOutputStream,
                PGPLiteralData.BINARY,
                PGPLiteralData.CONSOLE,
                data.length,
                new Date()
        );

        for (byte item : data) {
            literalOutputStream.write(item);
            pgpSignatureGenerator.update(item);
        }

        // Finish Literal Data construction
        literalOutputStream.close();

        // Output the actual signature
        pgpSignatureGenerator.generate().encode(bcpgOutputStream);

        // close off the stream.
        bcpgOutputStream.close();

        return byteArrayOutputStream.toByteArray();
    }


    // generates key pair
    public PGPKeyPair generateKeyPair(String algorithm, int algorithmTag, int keySize)
            throws NoSuchAlgorithmException, PGPException {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm);
        kpg.initialize(keySize, new SecureRandom());
        KeyPair keyPair = kpg.generateKeyPair();
        return new JcaPGPKeyPair(algorithmTag, keyPair, new Date());

    }

    private static JcaPGPContentSignerBuilder getJcaPGPContentSignerBuilder() {
        JcaPGPContentSignerBuilder jcaPGPContentSignerBuilder
                = new JcaPGPContentSignerBuilder(PublicKeyAlgorithmTags.DSA, HashAlgorithmTags.SHA1);
        jcaPGPContentSignerBuilder.setProvider(BC_PROVIDER);
        return jcaPGPContentSignerBuilder;
    }

    // TODO - needs some refactoring, al me jako mrzi sad
    public byte[] readSignedMessage(byte[] signedMessage, PGPPublicKey publicKey) throws Exception {
        JcaPGPObjectFactory jcaPGPObjectFactory = new JcaPGPObjectFactory(signedMessage);
        PGPOnePassSignatureList pgpOnePassSignatureList = (PGPOnePassSignatureList) jcaPGPObjectFactory.nextObject();

        PGPOnePassSignature header = pgpOnePassSignatureList.get(0);
        header.init(
                new JcaPGPContentVerifierBuilderProvider().setProvider("BC"),
                publicKey
        );

        ArrayList<Byte> message = new ArrayList<>();
        PGPLiteralData literalData = (PGPLiteralData) jcaPGPObjectFactory.nextObject();
        InputStream inputStream = literalData.getInputStream();

        // Read the message data
        int ch;
        while ((ch = inputStream.read()) >= 0) {
            header.update((byte) ch);
            message.add((byte) ch);
        }

        inputStream.close();

        // Read and verify the signature
        PGPSignatureList sigList = (PGPSignatureList) jcaPGPObjectFactory.nextObject();
        PGPSignature sig = sigList.get(0);

        boolean verify = header.verify(sig);
        if(!verify)
            throw new Exception("Invalid public key");

        Byte[] returnMessage = new Byte[message.size()];
        message.toArray(returnMessage);
        return ArrayUtils.toPrimitive(returnMessage);

    }



}

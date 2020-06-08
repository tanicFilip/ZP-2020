package pgp.utils;

import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.util.io.Streams;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pgp.Sender;

import java.io.*;
import java.security.*;
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
        PGPObjectFactory jcaPGPObjectFactory = new BcPGPObjectFactory(signedMessage);
        PGPOnePassSignatureList pgpOnePassSignatureList = (PGPOnePassSignatureList) jcaPGPObjectFactory.nextObject();

        PGPOnePassSignature header = pgpOnePassSignatureList.get(0);
        header.init(
                new BcPGPContentVerifierBuilderProvider(),
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

    public void readEncryptedFile(InputStream in) throws IOException, PGPException {
        in = PGPUtil.getDecoderStream(in);

        JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(in);
        PGPEncryptedDataList enc;
        Object o = pgpF.nextObject();

        //
        // the first object might be a PGP marker packet.
        //
        if (o instanceof PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) o;
        } else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
        }

        PGPPBEEncryptedData pbe = (PGPPBEEncryptedData) enc.get(0);

        InputStream clear = pbe.getDataStream(new JcePBEDataDecryptorFactoryBuilder(new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build()).setProvider("BC").build(Sender.password.toCharArray()));

        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(clear);

        //
        // if we're trying to read a file generated by someone other than us
        // the data might not be compressed, so we check the return type from
        // the factory and behave accordingly.
        //
        o = pgpFact.nextObject();
        if (o instanceof PGPCompressedData) {
            PGPCompressedData cData = (PGPCompressedData) o;

            pgpFact = new JcaPGPObjectFactory(cData.getDataStream());

            o = pgpFact.nextObject();
        }

        PGPLiteralData ld = (PGPLiteralData) o;
        InputStream unc = ld.getInputStream();

        OutputStream fOut = new BufferedOutputStream(new FileOutputStream("fuck.txt"));

        Streams.pipeAll(unc, fOut);

        if (pbe.isIntegrityProtected()) {
            if (!pbe.verify()) {
                System.err.println("message failed integrity check");
            } else {
                System.err.println("message integrity check passed");
            }
        } else {
            System.err.println("no message integrity check");
        }

        fOut.close();
    }


}

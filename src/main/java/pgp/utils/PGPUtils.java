package pgp.utils;

import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.bcpg.*;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.util.io.Streams;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pgp.Sender;
import pgp.exceptions.BadMessageException;
import pgp.exceptions.InvalidSignatureException;

import java.io.*;
import java.security.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.Objects;

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
        Date dateExpires = new Date();
        // two years worth of seconds added
        dateExpires.setTime(dateExpires.getTime() + 2 * 31536000000l);
        return new JcaPGPKeyPair(algorithmTag, keyPair, dateExpires);
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
            throw new InvalidSignatureException("Invalid public key");

        Byte[] returnMessage = new Byte[message.size()];
        message.toArray(returnMessage);
        return ArrayUtils.toPrimitive(returnMessage);

    }

    public byte[] compressData(String fileName) throws IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator comData = null;

        comData = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);

        PGPUtil.writeFileToLiteralData(comData.open(bOut), PGPLiteralData.BINARY, new File(fileName));

        comData.close();

        return bOut.toByteArray();
    }

    public byte[] convertToLiteralData(String fileName) throws IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        PGPUtil.writeFileToLiteralData(bOut, PGPLiteralData.BINARY, new File(fileName));

        return bOut.toByteArray();
    }

    public void encryptMessage(String sourceFileName, String encryptedFileName, String password, boolean shouldZIP)
            throws IOException, PGPException {

        OutputStream outputStream = new ArmoredOutputStream(new FileOutputStream(encryptedFileName));
        byte[] data;

        if(shouldZIP)
            data = compressData(sourceFileName);
        else
            data = convertToLiteralData(sourceFileName);

        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_128)
                .setWithIntegrityPacket(true).setSecureRandom(new SecureRandom()).setProvider("BC"));

        encGen.addMethod(new JcePBEKeyEncryptionMethodGenerator(password.toCharArray()).setProvider("BC"));

        OutputStream encOut = encGen.open(outputStream, data.length);
        encOut.write(data);

        encOut.close();
        encGen.close();
        outputStream.close();
    }

    public void readEncryptedFile(String outputFileName, String receivedFileName, String password)
            throws IOException, PGPException, BadMessageException {
        InputStream bufferedInputStream = null;
        OutputStream fOut = null;
        try {
            bufferedInputStream = new BufferedInputStream(new FileInputStream(receivedFileName));
            bufferedInputStream = PGPUtil.getDecoderStream(bufferedInputStream);

            var pgpObjectFactory = new JcaPGPObjectFactory(bufferedInputStream);
            PGPEncryptedDataList pgpEncryptedDataList;
            var nextObject = pgpObjectFactory.nextObject();


            // the first object might be a PGP marker packet.
            if (nextObject instanceof PGPEncryptedDataList) {
                pgpEncryptedDataList = (PGPEncryptedDataList) nextObject;
            } else {
                pgpEncryptedDataList = (PGPEncryptedDataList) pgpObjectFactory.nextObject();
            }

            var pgpPbeEncryptedData = (PGPPBEEncryptedData) pgpEncryptedDataList.get(0);

            // decrypted stream
            InputStream clear = pgpPbeEncryptedData.getDataStream(
                    new JcePBEDataDecryptorFactoryBuilder(
                            new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build()).setProvider("BC").build(password.toCharArray()
                    )
            );

            JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(clear);

            // file may not have been compressed
            nextObject = pgpFact.nextObject();
            if (nextObject instanceof PGPCompressedData) {
                PGPCompressedData cData = (PGPCompressedData) nextObject;

                pgpFact = new JcaPGPObjectFactory(cData.getDataStream());

                nextObject = pgpFact.nextObject();
            }


            PGPLiteralData ld = (PGPLiteralData) nextObject;
            InputStream unc = ld.getInputStream();

            fOut = new BufferedOutputStream(new FileOutputStream(outputFileName));

            Streams.pipeAll(unc, fOut);

            if (!pgpPbeEncryptedData.isIntegrityProtected() || !pgpPbeEncryptedData.verify()) {
                throw new BadMessageException();
            }
        }finally {
            if(Objects.nonNull(fOut))
                fOut.close();
            if(Objects.nonNull(bufferedInputStream))
                bufferedInputStream.close();
        }
    }


}

package openpgp.pgp.impl;

import openpgp.pgp.PGP;
import openpgp.utils.DataReadUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.bcpg.*;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.util.io.Streams;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import openpgp.exceptions.BadMessageException;
import openpgp.exceptions.InvalidSignatureException;
import openpgp.exceptions.PublicKeyRingDoesNotContainElGamalKey;

import java.io.*;
import java.security.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;

public class PGPImpl implements PGP {

    public static final String BC_PROVIDER = "BC";
    private static final Logger logger = LoggerFactory.getLogger(PGPImpl.class);

    // generates key pair
    @Override
    public PGPKeyPair generateKeyPair(String algorithm, int algorithmTag, int keySize) throws NoSuchAlgorithmException, PGPException {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm);
        kpg.initialize(keySize, new SecureRandom());
        KeyPair keyPair = kpg.generateKeyPair();
        return new JcaPGPKeyPair(algorithmTag, keyPair, new Date());

    }

    @Override
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

    @Override
    public byte[] readSignedMessage(byte[] signedMessage, PGPPublicKey publicKey) throws InvalidSignatureException, IOException, PGPException {
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

    @Override
    public void encryptMessage(String sourceFileName, String encryptedFileName, boolean shouldZIP, boolean shouldRadix, int algorithmTag, List<PGPKeyRing> receiverPublicKeys)
            throws IOException, PGPException, PublicKeyRingDoesNotContainElGamalKey {

        OutputStream outputStream;
        if(shouldRadix)
            outputStream = new ArmoredOutputStream(new FileOutputStream(encryptedFileName));
        else
            outputStream = new FileOutputStream(encryptedFileName);

        byte[] data;

        if(shouldZIP)
            data = compressData(sourceFileName);
        else
            data = convertToLiteralData(sourceFileName);

        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(algorithmTag)
                .setWithIntegrityPacket(true).setSecureRandom(new SecureRandom()).setProvider("BC"));

        for (PGPKeyRing receiverPublicKey : receiverPublicKeys) {
            var iterator = receiverPublicKey.getPublicKeys();
            PGPPublicKey elGamalKey = null;
            while(iterator.hasNext()){
                // UGLY!
                Object iterNext = iterator.next();
                if(!(iterNext instanceof PGPPublicKey)){
                    throw new PGPException("This was totally unexpected!");
                }
                PGPPublicKey item = (PGPPublicKey) iterNext;
                if(item.isEncryptionKey()){
                    elGamalKey = item;
                    break;
                }
            }
            if(Objects.isNull(elGamalKey))
                throw new PublicKeyRingDoesNotContainElGamalKey();

            encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(elGamalKey).setProvider("BC"));
        }

        OutputStream encOut = encGen.open(outputStream, data.length);
        encOut.write(data);

        encOut.close();
        encGen.close();
        outputStream.close();
    }

    @Override
    public byte[] verifyMessage(String inputFileName, PGPPublicKeyRingCollection receiversPublicKeyRingCollection) {
        byte[] decodedMessage = null;
        var publicKeyRingIterator = receiversPublicKeyRingCollection.iterator();
        while(publicKeyRingIterator.hasNext()){
            PGPPublicKey key = publicKeyRingIterator.next().getPublicKey();
            try{
                logger.info("Verifying signed message...");
                decodedMessage = readSignedMessage(DataReadUtils.readBytesFromFile(inputFileName), key);
                logger.info("Verified signed message");
                break;
            }catch(InvalidSignatureException | IOException e) {
                logger.warn("Failed to decrypt the message. Error message: {}", e.getMessage());
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return decodedMessage;
    }

    @Override
    public void decryptFile(String inputFileName, String outputFileName, String password, PGPSecretKeyRingCollection secretKeyRingCollection) {
        var elgamalIterator = secretKeyRingCollection.getKeyRings();
        while(elgamalIterator.hasNext()) {

            var elgamalKeyRing = elgamalIterator.next();
            var elgamalKeyRingIterator = elgamalKeyRing.iterator();
            PGPSecretKey secretKey = null;
            while(elgamalKeyRingIterator.hasNext()) {
                var item = elgamalKeyRingIterator.next();
                if(item.getPublicKey().getAlgorithm() == PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT){
                    secretKey = item;
                    break;
                }
            }
            if(secretKey == null){
                continue;
            }

            logger.info("Decrypting message...");
            try {
                PBESecretKeyDecryptor decryptorFactory = new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(password.toCharArray());
                readEncryptedFile(inputFileName, outputFileName, secretKey.extractPrivateKey(decryptorFactory));
                logger.info("Decrypted message.");
                break;
            }catch (Exception e){
                logger.info("Wrong key, try again");
            }
        }
    }

    private void readEncryptedFile(String inputFileName, String outputFileName, PGPPrivateKey pgpPrivateKey)
            throws IOException, PGPException, BadMessageException {
        InputStream bufferedInputStream = null;
        OutputStream fOut = null;
        try {
            bufferedInputStream = new BufferedInputStream(new FileInputStream(inputFileName));
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

            var pgpPbeEncryptedData = (PGPPublicKeyEncryptedData) pgpEncryptedDataList.get(0);

            // decrypted stream
            InputStream clear = pgpPbeEncryptedData.getDataStream(
                    new JcePublicKeyDataDecryptorFactoryBuilder().build(pgpPrivateKey)
            );

            JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(clear);

            // file may not have been compressed
            nextObject = pgpFact.nextObject();
            if (nextObject instanceof PGPCompressedData) {
                var compressedData = (PGPCompressedData) nextObject;
                pgpFact = new JcaPGPObjectFactory(compressedData.getDataStream());
                nextObject = pgpFact.nextObject();
            }


            PGPLiteralData pgpLiteralData = (PGPLiteralData) nextObject;
            InputStream unc = pgpLiteralData.getInputStream();

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

    // signing helper methods
    private static JcaPGPContentSignerBuilder getJcaPGPContentSignerBuilder() {
        JcaPGPContentSignerBuilder jcaPGPContentSignerBuilder
                = new JcaPGPContentSignerBuilder(PublicKeyAlgorithmTags.DSA, HashAlgorithmTags.SHA256);
        jcaPGPContentSignerBuilder.setProvider(BC_PROVIDER);
        return jcaPGPContentSignerBuilder;
    }

    // encryption helper methods
    private byte[] compressData(String fileName) throws IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        var compressedDataGenerator = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);

        PGPUtil.writeFileToLiteralData(compressedDataGenerator.open(bOut), PGPLiteralData.BINARY, new File(fileName));

        compressedDataGenerator.close();

        return bOut.toByteArray();
    }

    private byte[] convertToLiteralData(String fileName) throws IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        PGPUtil.writeFileToLiteralData(bOut, PGPLiteralData.BINARY, new File(fileName));

        return bOut.toByteArray();
    }


}

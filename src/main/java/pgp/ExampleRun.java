package pgp;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import pgp.utils.DataReadUtils;
import pgp.utils.DataWriteUtils;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Date;

public class ExampleRun {

  public static void init(){
    Security.addProvider(new BouncyCastleProvider());
  }

  public static void main(String[] args) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, PGPException, IOException {

    init();

    //byte[] data = DataReadUtils.readBytesFromString("RANDOM DATA");
    byte[] data = DataReadUtils.readBytesFromFile("example.txt");
    DataWriteUtils.writeBytesToConsole(data);
    DataWriteUtils.writeBytesToFile(data, "exampleOut.txt");


    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

    // Create a stream for writing a signature to.
    BCPGOutputStream bcpgOutputStream = new BCPGOutputStream(byteArrayOutputStream);


    JcaPGPContentSignerBuilder jcaPGPContentSignerBuilder = getJcaPGPContentSignerBuilder();
    PGPKeyPair keyPair = generateKeyPair();
    PGPSignatureGenerator pgpSignatureGenerator = new PGPSignatureGenerator(jcaPGPContentSignerBuilder);
    pgpSignatureGenerator.init(PGPSignature.BINARY_DOCUMENT, keyPair.getPrivateKey());

    pgpSignatureGenerator
        .generateOnePassVersion(false)
        .encode(bcpgOutputStream);

    PGPLiteralDataGenerator literalDataGenerator
        = new PGPLiteralDataGenerator();

    OutputStream literalOutputStream =
        literalDataGenerator.open(
            bcpgOutputStream,
            PGPLiteralData.BINARY,
            PGPLiteralData.CONSOLE,
            data.length,
            new Date()
        );

    for (int i = 0; i != data.length; i++) {
      literalOutputStream.write(data[i]);
      pgpSignatureGenerator.update(data[i]);
    }

    // Finish Literal Data construction
    literalOutputStream.close();

    // Output the actual signature
    pgpSignatureGenerator.generate().encode(bcpgOutputStream);

    // close off the stream.
    bcpgOutputStream.close();

    System.out.println(Arrays.toString(byteArrayOutputStream.toByteArray()));

    JcaPGPObjectFactory jcaPGPObjectFactory = new JcaPGPObjectFactory(byteArrayOutputStream.toByteArray());

    PGPOnePassSignatureList pgpOnePassSignatureList =
        (PGPOnePassSignatureList) jcaPGPObjectFactory.nextObject();

    PGPOnePassSignature header = pgpOnePassSignatureList.get(0);
    header.init(
        new JcaPGPContentVerifierBuilderProvider().setProvider("BC"),
        keyPair.getPublicKey()
    );

    PGPLiteralData literalData = (PGPLiteralData)jcaPGPObjectFactory.nextObject();
    InputStream inputStream = literalData.getInputStream();
    readHashedValue(keyPair, jcaPGPObjectFactory, header, inputStream);
    return;

  }

  private static void readHashedValue(PGPKeyPair keyPair, JcaPGPObjectFactory jcaPGPObjectFactory, PGPOnePassSignature header, InputStream inputStream) throws IOException, PGPException {
    // Read the message data
    int ch;
    while ((ch = inputStream.read()) >= 0) {
      header.update((byte)ch);
      System.out.println(ch);
    }

    inputStream.close();

    // Read and verify the signature
    PGPSignatureList sigList = (PGPSignatureList)jcaPGPObjectFactory.nextObject();
    PGPSignature sig = sigList.get(0);

    boolean verify = header.verify(sig);
    System.out.println(verify);

    // write public key to asc file
    ArmoredOutputStream pubout = new ArmoredOutputStream(new BufferedOutputStream(new FileOutputStream("dummy.asc")));
    keyPair.getPublicKey().encode(pubout);
    pubout.close();
  }

  private static PGPKeyPair generateKeyPair() throws NoSuchAlgorithmException, PGPException {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
    kpg.initialize(1024, new SecureRandom());
    KeyPair keyPair = kpg.generateKeyPair();
    return new JcaPGPKeyPair(PGPPublicKey.DSA, keyPair, new Date());
  }

  private static JcaPGPContentSignerBuilder getJcaPGPContentSignerBuilder() {
    JcaPGPContentSignerBuilder jcaPGPContentSignerBuilder
        = new JcaPGPContentSignerBuilder(PublicKeyAlgorithmTags.DSA, HashAlgorithmTags.SHA1);
    jcaPGPContentSignerBuilder.setProvider("BC");
    return jcaPGPContentSignerBuilder;
  }

}

package pgp.playground;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.UserAttributePacket;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.bc.BcPGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.bc.BcPGPSecretKeyRing;
import org.bouncycastle.openpgp.bc.BcPGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import pgp.exceptions.PublicKeyDoesNotExistException;
import pgp.utils.DataWriteUtils;
import pgp.utils.KeyRingUtils;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;



// Note = all classes in this package are here just to figure stuff out, and not much more. This can all be deleted
public class KeyRingPlayground {

    KeyRingUtils keyRingUtils = new KeyRingUtils();

    private BcPGPSecretKeyRingCollection secretKeyRings;
    private BcPGPPublicKeyRingCollection publicKeyRings;

    BcPGPSecretKeyRingCollection generateEmptySecretKeyRingCollection() throws IOException, PGPException {
        InputStream inputStream = PGPUtil.getDecoderStream(InputStream.nullInputStream());
        return new BcPGPSecretKeyRingCollection(inputStream);
    }

    PGPSecretKeyRing generateSecretKeyRing(String email, String password, PGPKeyPair pgpKeyPair) throws PGPException {
        PGPDigestCalculator sha1Calculator =
                new JcaPGPDigestCalculatorProviderBuilder()
                        .build()
                        .get(HashAlgorithmTags.SHA1);

        PGPContentSignerBuilder pgpContentSignerBuilder =
                new JcaPGPContentSignerBuilder(
                        pgpKeyPair.getPublicKey().getAlgorithm(),
                        HashAlgorithmTags.SHA384
                );

        PBESecretKeyEncryptor pbeSecretKeyEncryptor =
                new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calculator)
                        .setProvider("BC")
                        .build(password.toCharArray());

        PGPKeyRingGenerator keyRingGen =
                new PGPKeyRingGenerator(
                        PGPSignature.POSITIVE_CERTIFICATION,
                        pgpKeyPair,
                        email,
                        sha1Calculator,
                        null,
                        null,
                        pgpContentSignerBuilder,
                        pbeSecretKeyEncryptor
                );

        return keyRingGen.generateSecretKeyRing();
    }

    public void example(PGPKeyPair pgpKeyPair) throws IOException, PGPException {

        secretKeyRings = generateEmptySecretKeyRingCollection();

        String password = "PASSWORD";
        String email = "email";

        PGPSecretKeyRing pgpSecretKeys = generateSecretKeyRing(email, password, pgpKeyPair);

        PGPSecretKeyRingCollection.addSecretKeyRing(secretKeyRings, pgpSecretKeys);

        System.out.println(new String(pgpSecretKeys.getEncoded(), StandardCharsets.UTF_8));
        DataWriteUtils.writeBytesToFile(pgpSecretKeys.getEncoded(), "keyring.gpg");
    }

    public void exampleRead(PGPKeyPair pgpKeyPair) throws IOException, PGPException {
        InputStream inputStream = new ByteArrayInputStream(Files.readAllBytes(Paths.get("keyring.gpg")));
        BcPGPSecretKeyRingCollection keyRings = new BcPGPSecretKeyRingCollection(inputStream);

        try {
            keyRingUtils.findSecretKeyByPublicKey(keyRings, pgpKeyPair.getPublicKey());
        } catch (PublicKeyDoesNotExistException e) {
            System.out.println("Public key does not exist in this keyring");
        }


    }


    public static void main(String[] args) throws PGPException, NoSuchAlgorithmException, IOException {
        Security.addProvider(new BouncyCastleProvider());
        PGPKeyPair pgpKeyPair = generateKeyPair("DSA", PublicKeyAlgorithmTags.DSA, 1024);
        PGPKeyPair pgpKeyPair1 = generateKeyPair("DSA", PublicKeyAlgorithmTags.DSA, 1024);
        KeyRingPlayground keyRingPlayground = new KeyRingPlayground();
        keyRingPlayground.example(pgpKeyPair);
        keyRingPlayground.exampleRead(pgpKeyPair);
        keyRingPlayground.exampleRead(pgpKeyPair1);
    }

    private static PGPKeyPair generateKeyPair(String algorithm, int algorithmTag, int keySize)
            throws NoSuchAlgorithmException, PGPException {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm);
        kpg.initialize(keySize, new SecureRandom());
        KeyPair keyPair = kpg.generateKeyPair();
        return new JcaPGPKeyPair(algorithmTag, keyPair, new Date());

    }


}

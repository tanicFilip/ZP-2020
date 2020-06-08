package pgp.utils;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.util.io.Streams;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Objects;

public class DataReadUtils {

  public static byte[] readBytesFromString(String data) throws UnsupportedEncodingException {
    if(Objects.isNull(data))
      data = "";

    return data.getBytes(Charset.defaultCharset().name());
  }

  public static byte[] readBytesFromFile(String filename) throws IOException {
    return Files.readAllBytes(Paths.get(filename));
  }

  public static byte[] readBytesFromZipArchive(String zipFileName) throws IOException, PGPException {
    InputStream fileInputStream = new FileInputStream(zipFileName);
    PGPObjectFactory pgpFact = new BcPGPObjectFactory(fileInputStream);
    PGPCompressedData cData = (PGPCompressedData)pgpFact.nextObject();
    pgpFact = new BcPGPObjectFactory(cData.getDataStream());
    PGPLiteralData ld = (PGPLiteralData)pgpFact.nextObject();
    return Streams.readAll(ld.getInputStream());

  }


}


package etf.openpgp.tf160342dsm160425d.backend.openpgp.utils;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.util.io.Streams;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Objects;
import java.util.regex.Pattern;

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

  /**
   * Returns a list of Files which name matches the regex string
   *
   * @param root
   * @param regex
   * @return list of matching Files
   */
  public static File[] listFilesMatching(File root, String regex) {
    if(!root.isDirectory()) {
      throw new IllegalArgumentException(root + " is not a directory.");
    }
    final Pattern p = Pattern.compile(regex);
    return root.listFiles(file -> p.matcher(file.getName()).matches());
  }

  /**
   * Returns a list of Files which name does not match the regex string
   *
   * @param root
   * @param regex
   * @return list of non-matching Files
   */
  public static File[] listFilesNotMatching(File root, String regex) {
    if(!root.isDirectory()) {
      throw new IllegalArgumentException(root + " is not a directory.");
    }
    final Pattern p = Pattern.compile(regex);
    return root.listFiles(file -> !p.matcher(file.getName()).matches());
  }


}


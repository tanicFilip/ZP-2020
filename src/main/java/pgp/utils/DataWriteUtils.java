package pgp.utils;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.util.io.Streams;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Date;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class DataWriteUtils {

  public static void writeBytesToConsole(byte[] data) {
    for (byte item : data) {
      System.out.println(item);
    }
  }

  public static void writeBytesToFile(byte[] data, String filename) throws IOException {
    OutputStream outputStream = new FileOutputStream(filename);
    outputStream.write(data);
    outputStream.flush();
    outputStream.close();
    //Files.write(Paths.get(filename), data);
  }
}

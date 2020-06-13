package openpgp.utils;

import java.io.*;

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

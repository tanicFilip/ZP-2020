package pgp.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class DataWriteUtils {

  public static void writeBytesToConsole(byte[] data) {
    for (byte item : data) {
      System.out.println(item);
    }
  }

  public static void writeBytesToFile(byte[] data, String filename) throws IOException {
    Files.write(Paths.get(filename), data);
  }

  public static void zipDataToFile(String originalFileName, String zipFileName) throws IOException {
    // TODO - needs rewriting, this is just a copy paste

    FileOutputStream fos = new FileOutputStream(zipFileName);
    ZipOutputStream zipOut = new ZipOutputStream(fos);
    File fileToZip = new File(originalFileName);
    FileInputStream fis = new FileInputStream(fileToZip);
    ZipEntry zipEntry = new ZipEntry(fileToZip.getName());
    zipOut.putNextEntry(zipEntry);
    byte[] bytes = new byte[1024];
    int length;
    while ((length = fis.read(bytes)) >= 0) {
      zipOut.write(bytes, 0, length);
    }

    zipOut.close();
    fis.close();
    fos.close();

  }

}

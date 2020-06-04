package pgp.utils;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
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


}


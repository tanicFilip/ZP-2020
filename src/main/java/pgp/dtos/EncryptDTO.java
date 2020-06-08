package pgp.dtos;

public class EncryptDTO {
    private boolean shouldZip;
    private int keySize;
    private boolean shouldConvertToRadix64;
    private String message;
    private String fileName;
}

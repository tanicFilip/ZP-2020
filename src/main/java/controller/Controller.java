package controller;

import backend.Backend;
import gui.*;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.MenuItem;
import javafx.scene.control.RadioButton;
import javafx.scene.control.ToggleGroup;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.bouncycastle.util.encoders.Base64;

import java.awt.*;
import java.io.File;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;

/**
 * Controller class used to call util methods from pgp package
 */
public class Controller {

    static GenerateKeyStage generateKeyStage;
    static ExportKeyStage exportKeyStage;
    static SendMessageStage sendMessageStage;
    static ReceiveMessageStage receiveMessageStage;

    public static void initGenerateKeyPair(MenuItem menuItem, Stage primaryStage){
        menuItem.setOnAction(value -> {
            generateKeyStage = new GenerateKeyStage(primaryStage);
            generateKeyStage.setTitle("Generate a new key pair");
            generateKeyStage.show();
        });
    }

    public static void initImportKey(MenuItem menuItem, Stage primaryStage){
        menuItem.setOnAction(value -> {
            FileChooser importFromFile = new FileChooser();
            importFromFile.setTitle("Import a file...");

            File importFrom = importFromFile.showOpenDialog(primaryStage);

            if(importFrom != null){
                if(Backend.getInstance().importKey(importFrom)){
                    GUI.getInstance().alertInfo("Success!");
                    GUI.getInstance().updateInfo();
                }
                else{
                    GUI.getInstance().alertInfo("Failed!");
                }
            }
        });
    }

    private static KeyRingHumanFormat.KeyType selectedType = KeyRingHumanFormat.KeyType.PUBLIC;

    public static void initExportKey(MenuItem menuItem, Stage primaryStage){
        menuItem.setOnAction(value -> {
            if(GUI.getInstance().getSelected() == null){
                GUI.getInstance().alertInfo("Select a key first");
                return;
            }

            exportKeyStage = new ExportKeyStage(primaryStage, GUI.getInstance().getSelected());
            exportKeyStage.setTitle("Export keys");
            exportKeyStage.show();
        });
    }

    public static void initSendMessage(MenuItem menuItem, Stage primaryStage){
        menuItem.setOnAction(value -> {
            sendMessageStage = new SendMessageStage(primaryStage);
            sendMessageStage.setTitle("Send a message");
            sendMessageStage.show();
        });
    }

    public static void initReceiveMessage(MenuItem menuItem, Stage primaryStage){
        menuItem.setOnAction(value -> {
            receiveMessageStage = new ReceiveMessageStage(primaryStage);
            receiveMessageStage.setTitle("Receive a message");
            receiveMessageStage.show();
        });
    }

    public static void initBackButton(Button button, Scene sceneToNavigate){
        button.setOnAction(value -> {
            System.out.println("action 1");
        });
    }

    /**
     * Copy of a util method from keyRingUtils.
     * Decodes user's Id into name and email Strings.
     *
     * @param userId
     * @return user's name at [0] and user's email at [1]
     */
    private static String[] getUserCredentials(String userId){
        return userId.split("__");
    }

    public static ObservableList<KeyRingHumanFormat> getKeyRings(){
        var secretKeyRingCollection = Backend.getInstance().getSecretKeyRingCollection();
        var publicKeyRingCollection = Backend.getInstance().getPublicKeyRingCollection();

        ArrayList<KeyRingHumanFormat> keyRings = new ArrayList<>();

        var iteratorSecret = secretKeyRingCollection.getKeyRings();
        while (iteratorSecret.hasNext()){
            var keyRing = iteratorSecret.next();
            KeyRingHumanFormat newKeyRingHumanFormat = new KeyRingHumanFormat();

            String[] userIds = getUserCredentials(keyRing.getPublicKey().getUserIDs().next());
            newKeyRingHumanFormat.setName(userIds[0]);
            newKeyRingHumanFormat.setEmail(userIds[1]);

            newKeyRingHumanFormat.setDateCreated(keyRing.getPublicKey().getCreationTime());
            Date dateExpires = new Date();
            dateExpires.setTime(
                    keyRing.getPublicKey().getCreationTime().getTime() + keyRing.getPublicKey().getValidSeconds()
            );
            newKeyRingHumanFormat.setDateExpires(dateExpires);

            // check if this is necessary!
            if(keyRing.getPublicKey() == null){
                newKeyRingHumanFormat.setKeyType(KeyRingHumanFormat.KeyType.SECRET);
                newKeyRingHumanFormat.setMasterKeyFingerprint(
                        null
                );
            }
            else{
                newKeyRingHumanFormat.setKeyType(KeyRingHumanFormat.KeyType.PAIR);
                newKeyRingHumanFormat.setMasterKeyFingerprint(
                        Base64.toBase64String(keyRing.getPublicKey().getFingerprint())
                );
            }

            keyRings.add(newKeyRingHumanFormat);
        }

        var iteratorPublic = publicKeyRingCollection.getKeyRings();
        while(iteratorPublic.hasNext()){
            var keyRing = iteratorPublic.next();
            KeyRingHumanFormat newKeyRingHumanFormat = new KeyRingHumanFormat();

            String[] userIds = getUserCredentials(keyRing.getPublicKey().getUserIDs().next());
            newKeyRingHumanFormat.setName(userIds[0]);
            newKeyRingHumanFormat.setEmail(userIds[1]);

            newKeyRingHumanFormat.setDateCreated(keyRing.getPublicKey().getCreationTime());
            Date dateExpires = new Date();
            dateExpires.setTime(
                    keyRing.getPublicKey().getCreationTime().getTime() + keyRing.getPublicKey().getValidSeconds()
            );
            newKeyRingHumanFormat.setDateExpires(dateExpires);

            newKeyRingHumanFormat.setKeyType(KeyRingHumanFormat.KeyType.PUBLIC);
            newKeyRingHumanFormat.setMasterKeyFingerprint(
                    Base64.toBase64String(keyRing.getPublicKey().getFingerprint())
            );

            keyRings.add(newKeyRingHumanFormat);
        }

        return FXCollections.observableList(keyRings);
    }

    public static void generateKeyPair(String name, String email, String password, int keySizeDSA, int keySizeELGAMAL){

        if(Backend.getInstance().generateKeyPair(name, email, password, keySizeDSA, keySizeELGAMAL)){
            generateKeyStage.alertInfo("Sucess!");
            generateKeyStage.close();

            GUI.getInstance().updateInfo();
        }
        else{
            generateKeyStage.alertInfo("Failed!");
        }
    }

    public static void deleteKeyPair(KeyRingHumanFormat keyRingHumanFormat, String password){
        byte[] masterKeyFingerprint = Base64.decode(keyRingHumanFormat.getMasterKeyFingerprint());

        if(Backend.getInstance().removeKeyPair(
                keyRingHumanFormat.getName(),
                keyRingHumanFormat.getEmail(),
                password,
                masterKeyFingerprint,
                keyRingHumanFormat.getKeyType()
        )){
            GUI.getInstance().alertInfo("Sucess!");

            GUI.getInstance().updateInfo();
        }
        else{
            GUI.getInstance().alertInfo("Failed!");
        }
    }

    public static void exportKey(KeyRingHumanFormat keyRingHumanFormat, KeyRingHumanFormat.KeyType exportKeyType, String password, File exportTo){
        byte[] masterKeyFingerprint = Base64.decode(keyRingHumanFormat.getMasterKeyFingerprint());

        if(Backend.getInstance().exportKey(
                keyRingHumanFormat.getName(),
                keyRingHumanFormat.getEmail(),
                password,
                masterKeyFingerprint,
                keyRingHumanFormat.getKeyType(),
                exportKeyType,
                exportTo
        )){
            exportKeyStage.alertInfo("Success!");
            exportKeyStage.close();
        }
        else{
            exportKeyStage.alertInfo("Failed!");
        }
    }

    public static void sendMessage(
            File message,
            String privateFingerprint,
            String[] publicFingerPrints,
            String password,
            boolean encrypt,
            SendMessageStage.ENCRYPTION_ALGORITHM algorithm,
            boolean sign,
            boolean useZip,
            boolean convertToRadix64)
    {
        byte[] privateFingerprintByte = privateFingerprint != null ? Base64.decode(privateFingerprint) : null;
        byte[][] publicFingerPrintsByte = null;

        if(publicFingerPrints != null) {
            ArrayList<byte[]> publicFingerPrintsByteAL = new ArrayList<>();
            for (var publicFingerPrint : publicFingerPrints) {
                publicFingerPrintsByteAL.add(Base64.decode(publicFingerPrint));
            }
            publicFingerPrintsByte = publicFingerPrintsByteAL.toArray(new byte[publicFingerPrintsByteAL.size()][]);
        }

        if(Backend.getInstance().sendMessage(
                message,
                privateFingerprintByte,
                publicFingerPrintsByte,
                password,
                encrypt,
                algorithm,
                sign,
                useZip,
                convertToRadix64
        ))
        {
            sendMessageStage.alertInfo("Success!");
            sendMessageStage.close();
        }
        else{
            sendMessageStage.alertInfo("Failed!");
        }
    }

}

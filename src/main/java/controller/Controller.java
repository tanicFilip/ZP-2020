package controller;

import backend.Backend;
import gui.GenerateKeyStage;
import gui.KeyRingHumanFormat;
import javafx.collections.ObservableList;
import javafx.event.Event;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.ListView;
import javafx.scene.control.MenuItem;
import javafx.scene.control.TableView;
import javafx.stage.Stage;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;

import java.util.ArrayList;
import java.util.Date;

/**
 * Controller class used to call util methods from pgp package
 */
public class Controller {

    static GenerateKeyStage generateKeyStage;

    public static void initGenerateKeyPair(MenuItem menuItem, Stage primaryStage){
        menuItem.setOnAction(value -> {
            generateKeyStage = new GenerateKeyStage(primaryStage);
            generateKeyStage.setTitle("Generate a new key pair");
            generateKeyStage.show();
        });
    }

    public static void initEncryptMessage(MenuItem menuItem){
        menuItem.setOnAction(value -> {
            System.out.println("action 3");
        });
    }

    public static void  initDecryptMessage(MenuItem menuItem){
        menuItem.setOnAction(value -> {
            System.out.println("action 4");
            getKeyRings();
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

            newKeyRingHumanFormat.setKeyFingerprint(keyRing.getPublicKey().getFingerprint());

            keyRings.add(newKeyRingHumanFormat);
        }

        System.out.println(keyRings.get(0));

        return null;
    }

    public static void generateKeyPair(String name, String email, String password, int keySizeDSA, int keySizeELGAMAL){

        if(Backend.getInstance().generateKeyPair(name, email, password, keySizeDSA, keySizeELGAMAL)){
            generateKeyStage.alertInfo("Sucess!");
            generateKeyStage.close();
        }
        else{
            generateKeyStage.alertInfo("Failed!");
        }
    }

    public static void deleteKeyPair(String name, String email, String password){
        // To Do: Implement a call to some method from pgp package that generates a new key pair
    }

}

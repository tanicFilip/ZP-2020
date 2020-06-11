package gui;

import controller.Controller;
import javafx.application.Application;
import javafx.scene.Group;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.input.KeyCharacterCombination;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyCombination;
import javafx.stage.Stage;

public class GUI extends Application {

    private static Stage primaryStage;
    private static Scene mainScene;

    static MenuItem generateKeyPair = new MenuItem("Generate a new key pair");
    static MenuItem deleteKeyPair = new MenuItem("Delete a key pair");

    static MenuItem encryptMessage = new MenuItem("Encrypt a message");
    static MenuItem decryptMessage = new MenuItem("Decrypt a message");

    @Override
    public void start(Stage primaryStage) throws Exception {

        this.primaryStage = primaryStage;
        Group root = new Group();
        this.mainScene = new Scene(root,960,540);

        // Init menus
        MenuBar menuBar = new MenuBar();
        menuBar.prefWidthProperty().bind(primaryStage.widthProperty());

        Menu keyMenu = new Menu("Key");

        generateKeyPair = new MenuItem("Generate a new key pair");
        generateKeyPair.setAccelerator(
                new KeyCharacterCombination(String.valueOf(KeyCode.G), KeyCombination.CONTROL_DOWN)
        );
        Controller.initGenerateKeyPair(generateKeyPair, primaryStage);
        deleteKeyPair = new MenuItem("Delete a key pair");
        deleteKeyPair.setAccelerator(
                new KeyCharacterCombination(String.valueOf(KeyCode.DELETE))// why does it not work?
        );
        deleteKeyPair.setOnAction(event -> {
            Alert alert = new Alert(Alert.AlertType.CONFIRMATION, "Delete key pair?", ButtonType.YES, ButtonType.CANCEL);
            alert.showAndWait();

            if(alert.getResult() == ButtonType.YES) {
                //Controller.deleteKeyPair(Args...);
            }
        });

        keyMenu.getItems().addAll(generateKeyPair, deleteKeyPair);

        Menu messageMenu = new Menu("Message");

        encryptMessage = new MenuItem("Encrypt a message");
        encryptMessage.setAccelerator(
                new KeyCharacterCombination(String.valueOf(KeyCode.E), KeyCombination.CONTROL_DOWN)
        );
        Controller.initEncryptMessage(encryptMessage);
        decryptMessage = new MenuItem("Decrypt a message");
        decryptMessage.setAccelerator(
                new KeyCharacterCombination(String.valueOf(KeyCode.D), KeyCombination.CONTROL_DOWN)
        );
        Controller.initDecryptMessage(decryptMessage);

        messageMenu.getItems().addAll(encryptMessage, decryptMessage);

        // To Do: Implement a list view of existing keys

        menuBar.getMenus().addAll(keyMenu, messageMenu);

        root.getChildren().add(menuBar);

        primaryStage.setScene(mainScene);
        primaryStage.setTitle("ZP");
        primaryStage.show();
    }

    public static void main(String[] args) {
        launch();
    }

    public static void setScene(Scene sceneToSet){
        primaryStage.setScene(sceneToSet);
    }

}

package gui;

import controller.Controller;
import javafx.application.Application;
import javafx.scene.Group;
import javafx.scene.Scene;
import javafx.scene.control.Menu;
import javafx.scene.control.MenuBar;
import javafx.scene.control.MenuItem;
import javafx.stage.Stage;

public class GUI extends Application {

    static MenuItem generateKeyPair = new MenuItem("Generate a new key pair");
    static MenuItem deleteKeyPair = new MenuItem("Delete a key pair");

    static MenuItem encryptMessage = new MenuItem("Encrypt a message");
    static MenuItem decryptMessage = new MenuItem("Decrypt a message");

    @Override
    public void start(Stage primaryStage) throws Exception {

        Group root = new Group();
        Scene scene = new Scene(root,960,540);

        // Init menus
        MenuBar menuBar = new MenuBar();
        menuBar.prefWidthProperty().bind(primaryStage.widthProperty());

        Menu keyMenu = new Menu("Key");

        generateKeyPair = new MenuItem("Generate a new key pair");
        Controller.initGenerateKeyPair(generateKeyPair);
        deleteKeyPair = new MenuItem("Delete a key pair");
        Controller.initDeleteKeyPair(deleteKeyPair);

        keyMenu.getItems().addAll(generateKeyPair, deleteKeyPair);

        Menu messageMenu = new Menu("Message");

        encryptMessage = new MenuItem("Encrypt a message");
        Controller.initEncryptMessage(encryptMessage);
        decryptMessage = new MenuItem("Decrypt a message");
        Controller.initDecryptMessage(decryptMessage);

        messageMenu.getItems().addAll(encryptMessage, decryptMessage);

        // To Do: Implement a list view of existing keys

        menuBar.getMenus().addAll(keyMenu, messageMenu);

        root.getChildren().add(menuBar);

        primaryStage.setScene(scene);
        primaryStage.setTitle("ZP");
        primaryStage.show();
    }

    public static void main(String[] args) {
        launch();
    }
}

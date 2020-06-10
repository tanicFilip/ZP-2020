package controller;

import gui.GenerateKeyStage;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.MenuItem;
import javafx.stage.Stage;

public class ControllerGUI {

    public static void initGenerateKeyPair(MenuItem menuItem, Stage primaryStage){
        menuItem.setOnAction(value -> {
            GenerateKeyStage generateKeyStage = new GenerateKeyStage(primaryStage);
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
        });
    }

    public static void initBackButton(Button button, Scene sceneToNavigate){
        button.setOnAction(value -> {
            System.out.println("action 1");
        });
    }

}

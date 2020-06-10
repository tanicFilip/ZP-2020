package gui;

import controller.Controller;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.VBox;
import javafx.stage.Modality;
import javafx.stage.Stage;
import javafx.scene.control.Alert.*;

public class GenerateKeyStage extends Stage {

    public static enum ASYMMETRIC {
        DSA , ELGAMAL;
    }

    public static int KEY_SIZE_1024 = 1024;
    public static int KEY_SIZE_2048 = 2048;
    public static int KEY_SIZE_4096 = 4096;

    private ASYMMETRIC asymmetricAlgo = ASYMMETRIC.DSA;
    private int keySize = KEY_SIZE_1024;

    private VBox root;
    private Scene scene;

    public GenerateKeyStage(Stage primaryStage) {
        this.initModality(Modality.APPLICATION_MODAL);
        this.initOwner(primaryStage);

        root = new VBox();
        scene = new Scene(root,600,400);

        Label nameLabel = new Label("Name");
        TextField nameTextField = new TextField();

        Label emailLabel = new Label("Email");
        TextField emailTextField = new TextField();

        Label passwordLabel = new Label("Password");
        TextField passwordTextField = new TextField();

        ToggleGroup algorithmGroup = new ToggleGroup();
        GridPane radioButtonPane = new GridPane();
        radioButtonPane.setHgap(15);
        radioButtonPane.setVgap(5);

        ToggleGroup keySizeGroup = new ToggleGroup();

        Label keySizeLabel = new Label("Key size");
        radioButtonPane.add(keySizeLabel, 1, 0);

        RadioButton key1024Radio = new RadioButton("1024");
        key1024Radio.setSelected(true);
        key1024Radio.setOnAction(event -> {
            keySize = KEY_SIZE_1024;
        });
        key1024Radio.setToggleGroup(keySizeGroup);
        radioButtonPane.add(key1024Radio, 1, 1);

        RadioButton key2048Radio = new RadioButton("2048");
        key2048Radio.setOnAction(event -> {
            keySize = KEY_SIZE_2048;
        });
        key2048Radio.setToggleGroup(keySizeGroup);
        radioButtonPane.add(key2048Radio, 1, 2);

        RadioButton key4096Radio = new RadioButton("4096");
        key4096Radio.setOnAction(event -> {
            keySize = KEY_SIZE_4096;
        });
        key4096Radio.setToggleGroup(keySizeGroup);
        key4096Radio.setDisable(true);
        radioButtonPane.add(key4096Radio, 1, 3);

        Label algorithmLabel = new Label("Algorithm");
        radioButtonPane.add(algorithmLabel, 0, 0);

        RadioButton dsaRadio = new RadioButton("DSA");
        dsaRadio.setSelected(true);
        dsaRadio.setOnAction(event -> {
            asymmetricAlgo = ASYMMETRIC.DSA;
            key4096Radio.setDisable(true);
            if(keySize == KEY_SIZE_4096){
                keySize = KEY_SIZE_1024;
                key1024Radio.setSelected(true);
            }
        });
        dsaRadio.setToggleGroup(algorithmGroup);
        radioButtonPane.add(dsaRadio, 0, 1);

        RadioButton elgamalRadio = new RadioButton("ElGamal");
        elgamalRadio.setOnAction(event -> {
            asymmetricAlgo = ASYMMETRIC.ELGAMAL;
            key4096Radio.setDisable(false);
        });
        elgamalRadio.setToggleGroup(algorithmGroup);
        radioButtonPane.add(elgamalRadio, 0, 2);

        Button generateButton = new Button("Generate");
        generateButton.setOnAction(event -> {
            Alert alert = new Alert(AlertType.CONFIRMATION, "Create key pair?", ButtonType.YES, ButtonType.CANCEL);
            alert.showAndWait();

            if(alert.getResult() == ButtonType.YES) {
                Controller.generateKeyPair(
                        nameTextField.getText(),
                        emailTextField.getText(),
                        passwordTextField.getText(),
                        asymmetricAlgo,
                        keySize
                );
            }
        });

        root.getChildren().addAll(
                nameLabel,
                nameTextField,
                emailLabel,
                emailTextField,
                passwordLabel,
                passwordTextField,
                radioButtonPane,
                generateButton
        );

        this.setScene(this.scene);
    }

    public ASYMMETRIC getAsymmetricAlgo() {
        return asymmetricAlgo;
    }

    public int getKeySize() {
        return keySize;
    }

}

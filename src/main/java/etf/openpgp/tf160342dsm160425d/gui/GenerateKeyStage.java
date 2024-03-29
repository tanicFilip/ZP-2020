package etf.openpgp.tf160342dsm160425d.gui;

import etf.openpgp.tf160342dsm160425d.backend.Backend;
import etf.openpgp.tf160342dsm160425d.controller.Controller;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.VBox;
import javafx.stage.Modality;
import javafx.stage.Stage;
import javafx.scene.control.Alert.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;

/**
 * The type Generate key stage.
 */
public class GenerateKeyStage extends Stage {

    private int keySizeDSA = Backend.KEY_SIZE_1024;
    private int keySizeELGAMAL = Backend.KEY_SIZE_1024;

    private VBox root;
    private Scene scene;

    /**
     * Instantiates a new Generate key stage.
     *
     * @param primaryStage the primary stage
     */
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

        ToggleGroup keySizeDSAGroup = new ToggleGroup();

        Label keySizeDSALabel = new Label("DSA key size");
        radioButtonPane.add(keySizeDSALabel, 0, 0);

        RadioButton key1024RadioDSA = new RadioButton("1024");
        key1024RadioDSA.setSelected(true);
        key1024RadioDSA.setOnAction(event -> {
            keySizeDSA = Backend.KEY_SIZE_1024;
        });
        key1024RadioDSA.setToggleGroup(keySizeDSAGroup);
        radioButtonPane.add(key1024RadioDSA, 0, 1);

        RadioButton key2048RadioDSA = new RadioButton("2048");
        key2048RadioDSA.setOnAction(event -> {
            keySizeDSA = Backend.KEY_SIZE_2048;
        });
        key2048RadioDSA.setToggleGroup(keySizeDSAGroup);
        radioButtonPane.add(key2048RadioDSA, 0, 2);

        ToggleGroup keySizeELGAMALGroup = new ToggleGroup();

        Label keySizeELGAMALLabel = new Label("ElGamal key size");
        radioButtonPane.add(keySizeELGAMALLabel, 1, 0);

        RadioButton key1024RadioELGAMAL = new RadioButton("1024");
        key1024RadioELGAMAL.setSelected(true);
        key1024RadioELGAMAL.setOnAction(event -> {
            keySizeELGAMAL = Backend.KEY_SIZE_1024;
        });
        key1024RadioELGAMAL.setToggleGroup(keySizeELGAMALGroup);
        radioButtonPane.add(key1024RadioELGAMAL, 1, 1);

        RadioButton key2048RadioELGAMAL = new RadioButton("2048");
        key2048RadioELGAMAL.setOnAction(event -> {
            keySizeELGAMAL = Backend.KEY_SIZE_2048;
        });
        key2048RadioELGAMAL.setToggleGroup(keySizeELGAMALGroup);
        radioButtonPane.add(key2048RadioELGAMAL, 1, 2);

        RadioButton key4096RadioELGAMAL = new RadioButton("4096");
        key4096RadioELGAMAL.setOnAction(event -> {
            keySizeELGAMAL = Backend.KEY_SIZE_4096;
        });
        key4096RadioELGAMAL.setToggleGroup(keySizeELGAMALGroup);
        radioButtonPane.add(key4096RadioELGAMAL, 1, 3);

        Button generateButton = new Button("Generate");
        generateButton.setOnAction(event -> {
            Alert alert = new Alert(AlertType.CONFIRMATION, "Create key pair?", ButtonType.YES, ButtonType.CANCEL);
            alert.showAndWait();

            if(alert.getResult() == ButtonType.YES) {
                Controller.generateKeyPair(
                        nameTextField.getText(),
                        emailTextField.getText(),
                        passwordTextField.getText(),
                        keySizeDSA,
                        keySizeELGAMAL
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

    /**
     * Gets key size dsa.
     *
     * @return the key size dsa
     */
    public int getKeySizeDSA() {
        return keySizeDSA;
    }

    /**
     * Gets key size elgamal.
     *
     * @return the key size elgamal
     */
    public int getKeySizeELGAMAL() {
        return keySizeELGAMAL;
    }

    /**
     * Alert info.
     *
     * @param message the message
     */
    public void alertInfo(String message){
        Alert alert = null;
        if(message.contains("Failed")){
            alert = new Alert(Alert.AlertType.INFORMATION, "", ButtonType.OK);
            try {
                File file = new File("./assets/surprised_pikachu.png");
                InputStream imageInputStream = new FileInputStream(file);
                ImageView imageView = new ImageView(new Image(imageInputStream));
                imageView.setFitHeight(200);
                imageView.setFitWidth(200);
                alert.setGraphic(imageView);

            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        else{
            alert = new Alert(Alert.AlertType.INFORMATION, message, ButtonType.OK);
        }

        alert.showAndWait();
    }

}

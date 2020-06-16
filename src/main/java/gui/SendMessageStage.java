package gui;

import controller.Controller;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Pane;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Modality;
import javafx.stage.Stage;

import java.io.File;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Optional;

public class SendMessageStage extends Stage {

    public enum ENCRYPTION_ALGORITHM {
        ALGO_3DES, ALGO_AES
    }

    private VBox root;
    private Scene scene;

    private boolean encrypt = false;
    private ENCRYPTION_ALGORITHM algo = ENCRYPTION_ALGORITHM.ALGO_3DES;
    private boolean sign = false;
    private boolean useZip = false;
    private boolean convertToRadix64 = false;
    private File selectedFile;
    private ObservableList<KeyRingHumanFormat> publicKeys;
    private ObservableList<KeyRingHumanFormat> privateKeys;

    public SendMessageStage(Stage primaryStage) {
        this.initModality(Modality.APPLICATION_MODAL);
        this.initOwner(primaryStage);

        root = new VBox();
        scene = new Scene(root, 600, 400);

        ListView<String> publicKeysListView = new ListView<>();
        ArrayList<String> arrayList = new ArrayList<>();
        publicKeys = GUI.getInstance().getPublicKeys();
        for(var key : publicKeys){
            arrayList.add(key.getName() + " <" + key.getEmail() + ">");
        }
        publicKeysListView.setItems(FXCollections.observableList(arrayList));
        publicKeysListView.setDisable(true);

        ToggleGroup algoChooserToggleGroup = new ToggleGroup();
        RadioButton algo3DES = new RadioButton("3DES");
        algo3DES.setSelected(true);
        algo3DES.setDisable(true);
        algo3DES.setToggleGroup(algoChooserToggleGroup);
        algo3DES.setOnAction(event -> algo = ENCRYPTION_ALGORITHM.ALGO_3DES);

        RadioButton algoAES = new RadioButton("AES");
        algoAES.setDisable(true);
        algoAES.setToggleGroup(algoChooserToggleGroup);
        algoAES.setOnAction(event -> algo = ENCRYPTION_ALGORITHM.ALGO_AES);

        HBox algoChooserHBox = new HBox(algo3DES, algoAES);
        algoChooserHBox.setSpacing(5);

        CheckBox encryptCheckbox = new CheckBox("Encrypt using public key");
        encryptCheckbox.setOnAction(event -> {
            encrypt = encryptCheckbox.isSelected();
            if(encryptCheckbox.isSelected()){
                ArrayList<String> arrayListAux = new ArrayList<>();
                publicKeys = GUI.getInstance().getPublicKeys();
                for(var key : publicKeys){
                    arrayListAux.add(key.getName() + " <" + key.getEmail() + ">");
                }
                publicKeysListView.setItems(FXCollections.observableList(arrayListAux));
                publicKeysListView.setDisable(false);

                algo3DES.setDisable(false);
                algoAES.setDisable(false);
            }
            else{
                publicKeysListView.setDisable(true);

                algo3DES.setDisable(true);
                algoAES.setDisable(true);
            }
        });

        ListView<String> privateKeysListView = new ListView<>();
        arrayList = new ArrayList<>();
        privateKeys = GUI.getInstance().getPrivateKeys();
        for(var key : privateKeys){
            arrayList.add(key.getName() + " <" + key.getEmail() + ">");
        }
        privateKeysListView.setItems(FXCollections.observableList(arrayList));
        privateKeysListView.setDisable(true);

        CheckBox signCheckbox = new CheckBox("Sign using private key");
        signCheckbox.setOnAction(event -> {
            sign = signCheckbox.isSelected();
            if(signCheckbox.isSelected()){
                ArrayList<String> arrayListAux = new ArrayList<>();
                privateKeys = GUI.getInstance().getPrivateKeys();
                for(var key : privateKeys){
                    arrayListAux.add(key.getName() + " <" + key.getEmail() + ">");
                }
                privateKeysListView.setItems(FXCollections.observableList(arrayListAux));
                privateKeysListView.setDisable(false);
            }
            else{
                privateKeysListView.setDisable(true);
            }
        });

        CheckBox useZipCheckbox = new CheckBox("Use ZIP");
        useZipCheckbox.setOnAction(event -> useZip = useZipCheckbox.isSelected());

        CheckBox convertToRadix64Checkbox = new CheckBox("Convert to Radix64");
        convertToRadix64Checkbox.setOnAction(event -> convertToRadix64 = convertToRadix64Checkbox.isSelected());

        Label selectedFileNameLabel = new Label("");

        Button selectFileButton = new Button("Select file");
        selectFileButton.setOnAction(event -> {
            FileChooser fileChooser = new FileChooser();
            File targetFile = fileChooser.showOpenDialog(this);

            if(targetFile != null){
                selectedFileNameLabel.setText(targetFile.getName());
                selectedFile = targetFile;
            }
        });

        HBox fileSelectorPane = new HBox(selectFileButton, selectedFileNameLabel);
        fileSelectorPane.setSpacing(5);

        Button sendMessageButton = new Button("Send");
        sendMessageButton.setOnAction(event -> {
            if(selectedFile == null){
                alertInfo("Select a file containing the message first");
                return;
            }

            Dialog<String> passwordAndConfirmDialog = new Dialog<>();
            passwordAndConfirmDialog.setTitle("Send message dialog");
            if(sign){
                passwordAndConfirmDialog.setHeaderText("Password is required to sign a message");
            }
            else{
                passwordAndConfirmDialog.setHeaderText("Are You sure?");
            }

            ButtonType deleteButtonType = new ButtonType("Send", ButtonBar.ButtonData.OK_DONE);
            passwordAndConfirmDialog.getDialogPane().getButtonTypes().addAll(deleteButtonType, ButtonType.CANCEL);

            if(sign) {
                GridPane grid = new GridPane();
                grid.setHgap(10);
                grid.setVgap(10);
                grid.setPadding(new Insets(20, 150, 10, 10));
                PasswordField password = new PasswordField();
                password.setPromptText("password");

                grid.add(new Label("Password:"), 0, 0);
                grid.add(password, 1, 0);

                passwordAndConfirmDialog.getDialogPane().setContent(grid);
                passwordAndConfirmDialog.setResultConverter(dialogButton -> {
                    if (dialogButton == deleteButtonType) {
                        return password.getText();
                    }
                    return null;
                });
            }
            else {
                passwordAndConfirmDialog.setResultConverter(dialogButton -> {
                    if (dialogButton == deleteButtonType) {
                        return "";
                    }
                    return null;
                });
            }

            Optional<String> result = passwordAndConfirmDialog.showAndWait();

            if (!result.isEmpty()) {
                ArrayList<String> publicKeyFingerprints = null;
                if(encrypt){
                    publicKeyFingerprints = new ArrayList<>();
                    for(var selectedKeyIndex : publicKeysListView.getSelectionModel().getSelectedIndices()){
                        publicKeyFingerprints.add(publicKeys.get(selectedKeyIndex).getMasterKeyFingerprint());
                    }
                }
                String privateKeyFingerprint = null;
                if(sign){
                    privateKeyFingerprint = privateKeys.get(privateKeysListView.getSelectionModel().getSelectedIndex()).getMasterKeyFingerprint();
                }

                Controller.sendMessage(
                        selectedFile,
                        privateKeyFingerprint,
                        publicKeyFingerprints.toArray(new String[0]),
                        result.get(),
                        encrypt,
                        algo,
                        sign,
                        useZip,
                        convertToRadix64
                );
            }

        });

        root.setSpacing(10);
        root.getChildren().addAll(
                fileSelectorPane,
                encryptCheckbox,
                algoChooserHBox,
                publicKeysListView,
                signCheckbox,
                privateKeysListView,
                useZipCheckbox,
                convertToRadix64Checkbox,
                sendMessageButton
        );

        this.setScene(this.scene);

    }

    public void alertInfo(String message){
        Alert alert = new Alert(Alert.AlertType.INFORMATION, message, ButtonType.OK);
        alert.showAndWait();
    }

}

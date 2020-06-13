package gui;

import controller.Controller;
import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.scene.Group;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.control.ButtonBar.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.input.KeyCharacterCombination;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyCombination;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

import java.util.Optional;

public class GUI extends Application {

    private static GUI instance;

    public static GUI getInstance() {
        return instance;
    }

    private static Stage primaryStage;
    private static Scene mainScene;

    MenuItem generateKeyPair = new MenuItem("Generate a new key pair");
    MenuItem deleteKeyPair = new MenuItem("Delete a key pair");

    MenuItem encryptMessage = new MenuItem("Encrypt a message");
    MenuItem decryptMessage = new MenuItem("Decrypt a message");

    TableView<KeyRingHumanFormat> keyRingsTablewView = new TableView<>();

    public void updateInfo(){
        keyRingsTablewView.getItems().clear();

        keyRingsTablewView.getItems().addAll(Controller.getKeyRings());
    }

    @Override
    public void start(Stage primaryStage) throws Exception {

        instance = this;
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
            if(keyRingsTablewView.getSelectionModel().getSelectedItems().size() != 1){
                Alert alert = new Alert(Alert.AlertType.INFORMATION, "Select a key first", ButtonType.OK);
                alert.showAndWait();

                return;
            }

            Dialog<String> passwordAndConfirmDialog = new Dialog<>();
            passwordAndConfirmDialog.setTitle("Delete key dialog");
            passwordAndConfirmDialog.setHeaderText("Password is required to delete a key");

            ButtonType deleteButtonType = new ButtonType("Delete", ButtonData.OK_DONE);
            passwordAndConfirmDialog.getDialogPane().getButtonTypes().addAll(deleteButtonType, ButtonType.CANCEL);

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

            Optional<String> result = passwordAndConfirmDialog.showAndWait();

            if(!result.isEmpty()){
                Controller.deleteKeyPair(keyRingsTablewView.getSelectionModel().getSelectedItem(), result.get());
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

        menuBar.getMenus().addAll(keyMenu, messageMenu);

        // init TableView containing key rings and their info
        TableColumn<KeyRingHumanFormat, String> nameColumn = new TableColumn<>();
        nameColumn.setCellValueFactory(new PropertyValueFactory<>("name"));
        TableColumn<KeyRingHumanFormat, String> emailColumn = new TableColumn<>();
        emailColumn.setCellValueFactory(new PropertyValueFactory<>("email"));
        TableColumn<KeyRingHumanFormat, String> dateCreatedColumn = new TableColumn<>();
        dateCreatedColumn.setCellValueFactory(new PropertyValueFactory<>("dateCreated"));
        TableColumn<KeyRingHumanFormat, String> dateExpiresColumn = new TableColumn<>();
        dateExpiresColumn.setCellValueFactory(new PropertyValueFactory<>("dateExpires"));
        TableColumn<KeyRingHumanFormat, String> fingerprintColumn = new TableColumn<>();
        fingerprintColumn.setCellValueFactory(new PropertyValueFactory<>("masterPublicKeyFingerprint"));

        keyRingsTablewView.getColumns().addAll(
                nameColumn, emailColumn, dateCreatedColumn, dateExpiresColumn, fingerprintColumn
        );

        // initial data fetch
        updateInfo();

        VBox tableViewVBox = new VBox();
        tableViewVBox.getChildren().addAll(menuBar, keyRingsTablewView);
        tableViewVBox.setSpacing(10);

        root.getChildren().addAll(tableViewVBox);

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

    public void alertInfo(String message){
        Alert alert = new Alert(Alert.AlertType.INFORMATION, message, ButtonType.OK);
        alert.showAndWait();
    }

}

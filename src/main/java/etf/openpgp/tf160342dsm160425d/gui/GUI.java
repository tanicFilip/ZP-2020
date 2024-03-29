package etf.openpgp.tf160342dsm160425d.gui;

import etf.openpgp.tf160342dsm160425d.controller.Controller;
import javafx.application.Application;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.scene.Group;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.control.ButtonBar.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.input.KeyCharacterCombination;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyCombination;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

import javax.imageio.ImageIO;
import java.io.*;
import java.util.Optional;

/**
 * The type Gui.
 */
public class GUI extends Application {

    private static GUI instance;

    /**
     * Gets instance.
     *
     * @return the instance
     */
    public static GUI getInstance() {
        return instance;
    }

    private static Stage primaryStage;
    private static Scene mainScene;

    /**
     * The Generate key pair.
     */
    MenuItem generateKeyPair = new MenuItem("Generate a new key pair");
    /**
     * The Delete key pair.
     */
    MenuItem deleteKeyPair = new MenuItem("Delete a key pair");
    /**
     * The Import key.
     */
    MenuItem importKey = new MenuItem("Import a key");
    /**
     * The Export key.
     */
    MenuItem exportKey = new MenuItem("Export a key");

    /**
     * The Send message.
     */
    MenuItem sendMessage = new MenuItem("Encrypt a message");
    /**
     * The Receive message.
     */
    MenuItem receiveMessage = new MenuItem("Decrypt a message");

    /**
     * The Key rings table view.
     */
    TableView<KeyRingHumanFormat> keyRingsTableView = new TableView<>();

    /**
     * Update info.
     */
    public void updateInfo(){
        keyRingsTableView.getItems().clear();

        keyRingsTableView.getItems().addAll(Controller.getKeyRings());
    }

    /**
     * Get selected key ring human format.
     *
     * @return the key ring human format
     */
    public KeyRingHumanFormat getSelected(){
        return keyRingsTableView.getSelectionModel().getSelectedItem();
    }

    /**
     * Get public keys observable list.
     *
     * @return the observable list
     */
    public ObservableList<KeyRingHumanFormat> getPublicKeys(){
        return keyRingsTableView.getItems();
    }

    /**
     * Get private keys observable list.
     *
     * @return the observable list
     */
    public ObservableList<KeyRingHumanFormat> getPrivateKeys(){
        return keyRingsTableView.getItems().filtered(keyRingHumanFormat -> keyRingHumanFormat.getKeyType() == KeyRingHumanFormat.KeyType.PAIR);
    }

    @Override
    public void start(Stage primaryStage) throws Exception {

        Controller.cleanTempFiles();

        instance = this;
        this.primaryStage = primaryStage;
        Group root = new Group();
        this.mainScene = new Scene(root,960,540);

        // Init menus
        MenuBar menuBar = new MenuBar();
        menuBar.prefWidthProperty().bind(primaryStage.widthProperty());

        Menu keyMenu = new Menu("Key");

        generateKeyPair.setAccelerator(
                new KeyCharacterCombination(String.valueOf(KeyCode.G), KeyCombination.CONTROL_DOWN)
        );
        Controller.initGenerateKeyPair(generateKeyPair, primaryStage);

        deleteKeyPair.setAccelerator(
                new KeyCharacterCombination(String.valueOf(KeyCode.D), KeyCombination.CONTROL_DOWN)
        );
        deleteKeyPair.setOnAction(event -> {
            if(keyRingsTableView.getSelectionModel().getSelectedItems().size() != 1){
                Alert alert = new Alert(Alert.AlertType.INFORMATION, "Select a key first", ButtonType.OK);
                alert.showAndWait();

                return;
            }

            Dialog<String> passwordAndConfirmDialog = new Dialog<>();
            passwordAndConfirmDialog.setTitle("Delete key dialog");
            if(keyRingsTableView.getSelectionModel().getSelectedItem().getKeyType() == KeyRingHumanFormat.KeyType.PAIR){
                passwordAndConfirmDialog.setHeaderText("Password is required to delete a key");
            }
            else if(keyRingsTableView.getSelectionModel().getSelectedItem().getKeyType() == KeyRingHumanFormat.KeyType.PUBLIC){
                passwordAndConfirmDialog.setHeaderText("Are You sure?");
            }


            ButtonType deleteButtonType = new ButtonType("Delete", ButtonData.OK_DONE);
            passwordAndConfirmDialog.getDialogPane().getButtonTypes().addAll(deleteButtonType, ButtonType.CANCEL);

            if(keyRingsTableView.getSelectionModel().getSelectedItem().getKeyType() == KeyRingHumanFormat.KeyType.PAIR){
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
                    Controller.deleteKeyPair(keyRingsTableView.getSelectionModel().getSelectedItem(), result.get());
                }
            }
            else if(keyRingsTableView.getSelectionModel().getSelectedItem().getKeyType() == KeyRingHumanFormat.KeyType.PUBLIC){
                passwordAndConfirmDialog.setResultConverter(dialogButton -> {
                    if (dialogButton == deleteButtonType) {
                        return "";
                    }
                    return null;
                });

                var result = passwordAndConfirmDialog.showAndWait();

                Controller.deleteKeyPair(keyRingsTableView.getSelectionModel().getSelectedItem(), result.get());
            }

        });

        importKey.setAccelerator(
                new KeyCharacterCombination(String.valueOf(KeyCode.I), KeyCombination.CONTROL_DOWN)
        );
        Controller.initImportKey(importKey, primaryStage);

        exportKey.setAccelerator(
                new KeyCharacterCombination(String.valueOf(KeyCode.E), KeyCombination.CONTROL_DOWN)
        );
        Controller.initExportKey(exportKey, primaryStage);

        keyMenu.getItems().addAll(generateKeyPair, deleteKeyPair, new SeparatorMenuItem(), importKey, exportKey);

        Menu messageMenu = new Menu("Message");

        sendMessage = new MenuItem("Send message");
        sendMessage.setAccelerator(
                new KeyCharacterCombination(String.valueOf(KeyCode.S), KeyCombination.CONTROL_DOWN)
        );
        Controller.initSendMessage(sendMessage, primaryStage);
        receiveMessage = new MenuItem("Receive message");
        receiveMessage.setAccelerator(
                new KeyCharacterCombination(String.valueOf(KeyCode.R), KeyCombination.CONTROL_DOWN)
        );
        Controller.initReceiveMessage(receiveMessage, primaryStage);

        messageMenu.getItems().addAll(sendMessage, receiveMessage);

        menuBar.getMenus().addAll(keyMenu, messageMenu);

        // init TableView containing key rings and their info
        TableColumn<KeyRingHumanFormat, String> nameColumn = new TableColumn<>("Name");
        nameColumn.setCellValueFactory(new PropertyValueFactory<>("name"));
        TableColumn<KeyRingHumanFormat, String> emailColumn = new TableColumn<>("Email");
        emailColumn.setCellValueFactory(new PropertyValueFactory<>("email"));
        TableColumn<KeyRingHumanFormat, String> dateCreatedColumn = new TableColumn<>("Date created");
        dateCreatedColumn.setCellValueFactory(new PropertyValueFactory<>("dateCreated"));
        TableColumn<KeyRingHumanFormat, String> dateExpiresColumn = new TableColumn<>("Date expires");
        dateExpiresColumn.setCellValueFactory(new PropertyValueFactory<>("dateExpires"));
        TableColumn<KeyRingHumanFormat, String> fingerprintColumn = new TableColumn<>("Fingerprint");
        fingerprintColumn.setCellValueFactory(new PropertyValueFactory<>("masterKeyFingerprint"));
        TableColumn<KeyRingHumanFormat, String> keyTypeColumn = new TableColumn<>("Key type");
        keyTypeColumn.setCellValueFactory(new PropertyValueFactory<>("keyType"));

        keyRingsTableView.getColumns().addAll(
                nameColumn, emailColumn, dateCreatedColumn, dateExpiresColumn, fingerprintColumn, keyTypeColumn
        );

        // initial data fetch
        updateInfo();

        VBox tableViewVBox = new VBox();
        tableViewVBox.getChildren().addAll(menuBar, keyRingsTableView);
        tableViewVBox.setSpacing(10);

        root.getChildren().addAll(tableViewVBox);

        primaryStage.setScene(mainScene);
        primaryStage.setTitle("ZP");
        primaryStage.show();
    }

    /**
     * The entry point of application.
     *
     * @param args the input arguments
     */
    public static void main(String[] args) {
        launch();
    }

    /**
     * Set scene.
     *
     * @param sceneToSet the scene to set
     */
    public static void setScene(Scene sceneToSet){
        primaryStage.setScene(sceneToSet);
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

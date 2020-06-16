package etf.openpgp.tf160342dsm160425d.backend.gui;

import etf.openpgp.tf160342dsm160425d.backend.Backend;
import etf.openpgp.tf160342dsm160425d.backend.controller.Controller;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Label;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Modality;
import javafx.stage.Stage;

import java.io.File;

/**
 * The type Receive message stage.
 */
public class ReceiveMessageStage extends Stage {

    private VBox root;
    private Scene scene;

    private File selectedFile;

    /**
     * Instantiates a new Receive message stage.
     *
     * @param primaryStage the primary stage
     */
    public ReceiveMessageStage(Stage primaryStage) {
        this.initModality(Modality.APPLICATION_MODAL);
        this.initOwner(primaryStage);

        root = new VBox();
        scene = new Scene(root, 600, 400);

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

        Button receiveMessageButton = new Button("Receive");
        receiveMessageButton.setOnAction(event -> {
            if(selectedFile == null){
                alertInfo("Select a file containing the message first");
                return;
            }

            Controller.receiveMessage(selectedFile);
        });

        root.setSpacing(10);
        root.getChildren().addAll(fileSelectorPane, receiveMessageButton);

        this.setScene(this.scene);
    }

    /**
     * Alert info.
     *
     * @param message the message
     */
    public void alertInfo(String message){
        Alert alert = new Alert(Alert.AlertType.INFORMATION, message, ButtonType.OK);
        alert.showAndWait();
    }

}

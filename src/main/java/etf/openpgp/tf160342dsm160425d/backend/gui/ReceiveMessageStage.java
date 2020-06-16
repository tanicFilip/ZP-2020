package etf.openpgp.tf160342dsm160425d.backend.gui;

import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.ButtonType;
import javafx.scene.layout.VBox;
import javafx.stage.Modality;
import javafx.stage.Stage;

public class ReceiveMessageStage extends Stage {

    private VBox root;
    private Scene scene;

    private KeyRingHumanFormat.KeyType selectedType = KeyRingHumanFormat.KeyType.PUBLIC;

    public ReceiveMessageStage(Stage primaryStage) {
        this.initModality(Modality.APPLICATION_MODAL);
        this.initOwner(primaryStage);

        root = new VBox();
        scene = new Scene(root, 600, 400);
    }

    public void alertInfo(String message){
        Alert alert = new Alert(Alert.AlertType.INFORMATION, message, ButtonType.OK);
        alert.showAndWait();
    }

}

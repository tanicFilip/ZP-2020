package etf.openpgp.tf160342dsm160425d.gui;

import etf.openpgp.tf160342dsm160425d.controller.Controller;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Modality;
import javafx.stage.Stage;

import java.io.File;
import java.util.Calendar;

/**
 * The type Export key stage.
 */
public class ExportKeyStage extends Stage {

    private VBox root;
    private Scene scene;

    private KeyRingHumanFormat.KeyType selectedType = KeyRingHumanFormat.KeyType.PUBLIC;

    /**
     * Instantiates a new Export key stage.
     *
     * @param primaryStage the primary stage
     * @param selected     the selected
     */
    public ExportKeyStage(Stage primaryStage, KeyRingHumanFormat selected){
        this.initModality(Modality.APPLICATION_MODAL);
        this.initOwner(primaryStage);

        root = new VBox();
        scene = new Scene(root,600,400);

        Label passwordLabel = new Label("Password");
        PasswordField passwordTextField = new PasswordField();
        passwordTextField.setDisable(true);

        Label typeLabel = new Label("Export:");
        ToggleGroup typeToExport = new ToggleGroup();

        RadioButton exportPair = new RadioButton("Secret");
        exportPair.setToggleGroup(typeToExport);
        if(selected.getKeyType() == KeyRingHumanFormat.KeyType.PUBLIC){
            exportPair.setDisable(true);
        }
        exportPair.setOnAction(event -> {
            selectedType = KeyRingHumanFormat.KeyType.PAIR;
            passwordTextField.setDisable(false);
        });

        RadioButton exportPublic = new RadioButton("Public");
        exportPublic.setToggleGroup(typeToExport);
        exportPublic.setSelected(true);
        exportPublic.setOnAction(event -> {
            selectedType = KeyRingHumanFormat.KeyType.PUBLIC;
            passwordTextField.setDisable(true);
        });

        FileChooser exportToFile = new FileChooser();
        exportToFile.setTitle("Export to file...");

        Button exportButton = new Button("Export");
        exportButton.setOnAction(event -> {
            exportToFile.setInitialFileName("" + Calendar.getInstance().getTimeInMillis() + ".asc");
            File exportTo = exportToFile.showSaveDialog(this);

            if(exportTo != null){
                Controller.exportKey(selected, selectedType, passwordTextField.getText(), exportTo);
            }
        });

        root.setSpacing(10);
        root.getChildren().addAll(
                typeLabel,
                exportPair,
                exportPublic,
                passwordLabel,
                passwordTextField,
                exportButton
        );

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

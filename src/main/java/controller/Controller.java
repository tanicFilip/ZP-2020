package controller;

import javafx.event.Event;
import javafx.scene.control.MenuItem;

/**
 * Controller class used to call util methods from pgp package
 */
public class Controller {

    public static void  initGenerateKeyPair(MenuItem menuItem){
        menuItem.setOnAction(value -> {
            System.out.println("action 1");
        });
    }

    public static void  initDeleteKeyPair(MenuItem menuItem){
        menuItem.setOnAction(value -> {
            System.out.println("action 2");
        });
    }

    public static void  initEncryptMessage(MenuItem menuItem){
        menuItem.setOnAction(value -> {
            System.out.println("action 3");
        });
    }

    public static void  initDecryptMessage(MenuItem menuItem){
        menuItem.setOnAction(value -> {
            System.out.println("action 4");
        });
    }

}

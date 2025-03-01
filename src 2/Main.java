import java.util.ArrayList;

import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.Stage;

public class Main extends Application {

    private KDC kdc;
    private Client client;
    private Server server;
    private TicketGrant ticketGrant;

    @Override
    public void start(Stage primaryStage) throws Exception {
        kdc = new KDC();
        ticketGrant = new TicketGrant();

        Label clientLabel = new Label("Client ID:");
        TextField clientField = new TextField();
        Label passwordLabel = new Label("Password:");
        PasswordField passwordField = new PasswordField();
        Label serverLabel = new Label("Server ID:");
        TextField serverField = new TextField();
        Label messageLabel = new Label("Message:");
        TextField messageField = new TextField();
        TextArea logArea = new TextArea();
        logArea.setEditable(false);

        Button registerButton = new Button("Register");
        Button loginButton = new Button("LogIn");
        Button communicateButton = new Button("Communicate with Server");

        registerButton.setOnAction(e -> {
            String clientId = clientField.getText().trim();
            String password = passwordField.getText().trim();
            String serverId = serverField.getText().trim();

            if (!clientId.isEmpty() && !password.isEmpty()) {
                if (kdc.registerClient(clientId, password)){
                    logArea.appendText("Client " + clientId + " registered successfully.\n");
                    Logger.log("Client " + clientId + " registered successfully.\n");
                }
                else {
                    logArea.appendText("Client id already exists in the system.\n");
                    Logger.log("Client id already exists in the system.\n");
                }
            }


            if (!serverId.isEmpty()) {
                if (kdc.registerServer(serverId)){
                    logArea.appendText("Server " + serverId + " registered successfully.\n");
                    Logger.log("Server " + serverId + " registered successfully.\n");
                }
                else {
                    logArea.appendText("Server id already exists in the system.\n");
                    Logger.log("Server id already exists in the system.\n");
                }
            }
        });

        loginButton.setOnAction(e -> {
            String clientId = clientField.getText().trim();
            String password = passwordField.getText().trim();
            String serverId = serverField.getText().trim();

            if (!clientId.isEmpty() && !password.isEmpty() && !serverId.isEmpty()) {
                int loginResponse = kdc.login(clientId, password, serverId);
                if (loginResponse == 1){
                    logArea.appendText("Login successful. Ticket issued for client: " + clientId + " and server: " + serverId + "\n");
                    Logger.log("Login successful. Ticket issued for client: " + clientId + " and server: " + serverId + "\n");
                    ArrayList<String> rsaPublicandPrivateClient = kdc.returnRSA(clientId);
                    ArrayList<String> rsaPublicandPrivateServer = kdc.returnRSA(serverId);
                    if (rsaPublicandPrivateClient.size() == 2 && rsaPublicandPrivateServer.size() == 2){
                        client = new Client(clientId, password, rsaPublicandPrivateClient.get(0), rsaPublicandPrivateClient.get(1));
                        server = new Server(serverId, rsaPublicandPrivateServer.get(0), rsaPublicandPrivateServer.get(1));
                        client.setTicket(kdc.rsaSessionKey(ticketGrant.generateTicket(clientId, serverId, 5)));
                        System.out.println("Encrypted session key (Client): " + client.getTicket().getEncryptedSessionKey());
                    }
                    else {
                        logArea.appendText("An error occured during retrieval of RSA keys. \n");
                        Logger.log("An error occured during retrieval of RSA keys. \n");
                    }
                }
                else if (loginResponse == 0){
                    logArea.appendText("Login failed: Wrong client id or password. \n");
                    Logger.log("Login failed: Wrong client id or password. \n");
                }
                else {
                    logArea.appendText("Login failed: The server does not exist in the system. \n");
                    Logger.log("Login failed: The server does not exist in the system. \n");
                }
            } else {
                logArea.appendText("Login failed: Ensure all fields are filled.\n");
                Logger.log("Login failed: Ensure all fields are filled.\n");
            }
        });

        communicateButton.setOnAction(e -> {
            String message = messageField.getText().trim();
            if (client != null && server != null && !message.isEmpty()) {
                try {
                    System.out.println("Attempting to get session key from client...");
                    System.out.println("Calling server.firstVersionSessionKey with encrypted session key: " + client.sessionKeyForServer());
                    String serverSessionKeyFirstVersion = server.firstVersionSessionKey(client.sessionKeyForServer());
                    if (serverSessionKeyFirstVersion.equals(client.getTicket().getEncryptedSessionKey())){
                        client.communicateWithServer(server, message);
                        logArea.appendText("Message sent to server: " + message + "\n");
                        Logger.log("Message sent to server: " + message + "\n");
                    }
                }
                catch (Exception e1) {
                    System.err.println("Error during rsa decryption: " + e1.getMessage());
                }
            } else {
                logArea.appendText("Communication failed: Ensure login and message are complete.\n");
                Logger.log("Communication failed: Ensure login and message are complete.\n");
            }
        });

        VBox root = new VBox(10,
            new HBox(10, clientLabel, clientField),
            new HBox(10, passwordLabel, passwordField),
            new HBox(10, serverLabel, serverField),
            new HBox(10, messageLabel, messageField),
            new HBox(10, registerButton, loginButton, communicateButton),
            new Label("Logs:"),
            logArea
        );
        root.setPadding(new Insets(10));

        Scene scene = new Scene(root, 600, 400);
        primaryStage.setScene(scene);
        primaryStage.setTitle("Kerberos Hybrid System");
        primaryStage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}

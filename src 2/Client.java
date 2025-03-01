import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;

import javax.crypto.Cipher;

public class Client {
    private String clientId;
    private String password;
    private String publicKey;
    private String privateKey;
    private Ticket ticket;

    public Client(String clientId, String password, String publicKey, String privateKey) {
        this.clientId = clientId;
        this.password = password;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public void setTicket(Ticket ticket) {
        this.ticket = ticket;
    }

    public String sessionKeyForServer() throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(this.privateKey);

        // Convert the private key bytes into a PrivateKey object
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKeyObj = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));

        // Initialize the RSA Cipher for decryption
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKeyObj);

        // Decode the Base64 encrypted data and decrypt it
        byte[] encryptedBytes = Base64.getDecoder().decode(this.ticket.getEncryptedSessionKey());
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        // Return the decrypted plaintext as a string
        return new String(decryptedBytes);
    }

    public Ticket getTicket() {
        return ticket;
    }

    public String getClientId() {
        return clientId;
    }

    public String getPassword() {
        return password;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void registerWithKDC() {
        System.out.println("Client " + clientId + " registered with KDC.");
    }

    public void login(String enteredPassword) {
        if (this.password.equals(enteredPassword)) {
            System.out.println("Login successful for client: " + clientId);
        } else {
            System.err.println("Login failed: Incorrect password.");
        }
    }

    public void communicateWithServer(Server server, String message) {
        try {
            System.out.println("Encrypting message with session key...");
            String encryptedMessage = Base64.getEncoder().encodeToString(message.getBytes()); // Placeholder encryption
            server.receiveMessage(encryptedMessage);
        } catch (Exception e) {
            System.err.println("Communication error: " + e.getMessage());
        }
    }
}

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

public class Server {
    private String serverId;
    private String publicKey;
    private String privateKey;

    public Server(String serverId, String publicKey, String privateKey) {
        this.serverId = serverId;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public String firstVersionSessionKey(String encryptedSessionkey) throws Exception{
        System.out.println("Encrypted session key (Server): " + encryptedSessionkey);

        byte[] keyBytes = Base64.getDecoder().decode(this.privateKey);

        // Convert the private key bytes into a PrivateKey object
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKeyObj = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));

        // Initialize the RSA Cipher for decryption
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKeyObj);

        // Decode the Base64 encrypted data and decrypt it
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedSessionkey);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        // Return the decrypted plaintext as a string
        return new String(decryptedBytes);
    }

    public String getServerId() {
        return serverId;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void registerWithKDC() {
        System.out.println("Server " + serverId + " registered with KDC.");
    }

    public void receiveMessage(String encryptedMessage) {
        try {
            System.out.println("Decrypting message with session key...");
            String decryptedMessage = new String(Base64.getDecoder().decode(encryptedMessage)); // Placeholder decryption
            System.out.println("Received message: " + decryptedMessage);
        } catch (Exception e) {
            System.err.println("Error decrypting message: " + e.getMessage());
        }
    }
}


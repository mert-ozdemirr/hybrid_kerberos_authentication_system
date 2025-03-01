import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.security.SecureRandom;

public class Ticket {
    private String encryptedSessionKey;
    private String clientId;
    private String serverId;
    private LocalDateTime expirationTime;
    private SecretKey aesKey; // Store the AES key for decryption (if needed)
    private String rsaSessionKey;

    public Ticket(String sessionKey, String clientId, String serverId, int validityMinutes) {
        this.clientId = clientId;
        this.serverId = serverId;
        this.expirationTime = LocalDateTime.now().plus(validityMinutes, ChronoUnit.MINUTES);

        try {
            // Generate AES Key
            this.aesKey = generateAESKey();

            // Encrypt session key
            this.encryptedSessionKey = encryptSessionKey(sessionKey, aesKey);
        } catch (Exception e) {
            throw new RuntimeException("Error during AES encryption: " + e.getMessage(), e);
        }
    }

    // Method to generate a random AES key (128-bit)
    private static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // 128-bit AES
        return keyGen.generateKey();
    }

    // Method to encrypt the session key using AES
    private static String encryptSessionKey(String sessionKey, SecretKey aesKey) throws Exception {
        // Create an IV (Initialization Vector)
        byte[] iv = new byte[16]; // 16 bytes for AES (128-bit block size)
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Initialize AES Cipher in CBC mode with PKCS5Padding
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);

        // Encrypt the session key
        byte[] encryptedBytes = cipher.doFinal(sessionKey.getBytes());

        // Combine IV and encrypted data for storage
        byte[] encryptedDataWithIV = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, encryptedDataWithIV, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, encryptedDataWithIV, iv.length, encryptedBytes.length);

        // Encode to Base64 for easy storage
        return Base64.getEncoder().encodeToString(encryptedDataWithIV);
    }

    public String getEncryptedSessionKey() {
        return encryptedSessionKey;
    }

    public void setrsaSessionKey(String newrsaSessionKey) {
        this.rsaSessionKey = newrsaSessionKey;
    }

    public String getClientId() {
        return clientId;
    }

    public String getServerId() {
        return serverId;
    }

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expirationTime);
    }

    public void displayTicketDetails() {
        System.out.println("Ticket Details:");
        System.out.println("Client ID: " + clientId);
        System.out.println("Server ID: " + serverId);
        System.out.println("Encrypted Session Key: " + encryptedSessionKey);
        System.out.println("Expiration Time: " + expirationTime);
    }

    public static void main(String[] args) {
        // Example usage
        Ticket ticket = new Ticket("sampleSessionKey", "Client1", "Server1", 5);
        ticket.displayTicketDetails();

        // Simulate ticket expiration check
        System.out.println("Is ticket expired? " + ticket.isExpired());
    }
}

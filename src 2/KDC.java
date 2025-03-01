import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class KDC {

    private static final String DATASET_FILE = "dataset.csv";

    public static void main(String[] args) {
        // Example usage
        registerClient("Client1", "password123");
        registerServer("Server1");
    }

    private static String hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = md.digest(password.getBytes());
        return Base64.getEncoder().encodeToString(hashBytes);
    }

    private static boolean idExists(String id) {
        try (BufferedReader reader = new BufferedReader(new FileReader(DATASET_FILE))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] data = line.split(",");
                String existingID = data[0].trim();

                if (existingID.equals(id)) {
                    return true; // ID already exists
                }
            }
        } catch (IOException e) {
            System.err.println("Error checking ID: " + e.getMessage());
        }
        return false; // ID does not exist
    }

    public static boolean registerClient(String clientId, String password) {
        if (idExists(clientId)) {
            System.out.println("Error: A client or server with this ID already exists.");
            return false;
        }
        
        try {
            // Generate RSA Key Pair
            KeyPair keyPair = generateRSAKeyPair();

            // Encode keys to Base64
            String publicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            String privateKey = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());

            // Save to dataset.csv
            saveToDataset(clientId, hashPassword(password), publicKey, privateKey, "client");

            System.out.println("Client registered successfully.");
            return true;
        } catch (Exception e) {
            System.err.println("Error registering client: " + e.getMessage());
            return false;
        }
    }

    public static boolean registerServer(String serverId) {
        if (idExists(serverId)) {
            System.out.println("Error: A client or server with this ID already exists.");
            return false;
        }

        try {
            // Generate RSA Key Pair
            KeyPair keyPair = generateRSAKeyPair();

            // Encode keys to Base64
            String publicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            String privateKey = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());

            // Save to dataset.csv
            saveToDataset(serverId, "", publicKey, privateKey, "server");

            System.out.println("Server registered successfully.");

            return true;
        } catch (Exception e) {
            System.err.println("Error registering server: " + e.getMessage());
            return false;
        }
    }

    private static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // Key size
        return keyPairGenerator.generateKeyPair();
    }

    private static void saveToDataset(String id, String password, String publicKey, String privateKey, String type) {
        try (FileWriter writer = new FileWriter(DATASET_FILE, true)) {
            writer.append(id).append(",")
                  .append(password).append(",")
                  .append(publicKey).append(",")
                  .append(privateKey).append(",")
                  .append(type).append("\n");
        } catch (IOException e) {
            System.err.println("Error writing to dataset file: " + e.getMessage());
        }
    }

    public static int login(String clientId, String password, String serverId) {
        if (!idExists(serverId)) {
            System.out.println("Error: The server is not registered to the system. \n");
            return -1;
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(DATASET_FILE))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] data = line.split(",");
                String storedUsername = data[0].trim();
                String storedHash = data[1].trim();

                // Check username match
                if (storedUsername.equals(clientId)) {
                    // Hash the entered password and compare with stored hash
                    String enteredHash = hashPassword(password);
                    if (enteredHash.equals(storedHash)){
                        return 1;
                    }
                }
            }
        } catch (IOException | NoSuchAlgorithmException e) {
            System.err.println("Error during login: " + e.getMessage());
        }

        return 0; // Login failed
    }

    public static ArrayList<String> returnRSA(String clientId) {
        ArrayList<String> rsaPair = new ArrayList<String>();

        try (BufferedReader reader = new BufferedReader(new FileReader(DATASET_FILE))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] data = line.split(",");
                String storedUsername = data[0].trim();
                String storedPublicKey = data[2].trim();
                String storedPrivateKey = data[3].trim();
                

                // Check username match
                if (storedUsername.equals(clientId)) {
                    rsaPair.add(storedPublicKey);
                    rsaPair.add(storedPrivateKey);
                    return rsaPair;
                }
            }
        } catch (IOException e) {
            System.err.println("Error during rsa retrieval: " + e.getMessage());
        }

        return rsaPair; // Login failed
    }

    public static String encryptLargeDataWithRSA(String data, String publicKey) throws Exception {
        // Generate a random AES key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // 128-bit AES
        SecretKey aesKey = keyGen.generateKey();

        // Encrypt data with AES
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[16]; // 16 bytes for AES
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
        byte[] encryptedData = aesCipher.doFinal(data.getBytes());

        // Encrypt AES key with RSA
        byte[] rsaKeyBytes = Base64.getDecoder().decode(publicKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKeyObj = keyFactory.generatePublic(new X509EncodedKeySpec(rsaKeyBytes));
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKeyObj);
        byte[] encryptedAESKey = rsaCipher.doFinal(aesKey.getEncoded());

        // Combine encrypted AES key, IV, and encrypted data
        byte[] combined = new byte[iv.length + encryptedAESKey.length + encryptedData.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encryptedAESKey, 0, combined, iv.length, encryptedAESKey.length);
        System.arraycopy(encryptedData, 0, combined, iv.length + encryptedAESKey.length, encryptedData.length);

        // Return Base64-encoded combined data
        return Base64.getEncoder().encodeToString(combined);
    }


    public static Ticket rsaSessionKey (Ticket createdTicket) {
        String serverId = createdTicket.getServerId();
        String clientId = createdTicket.getClientId();

        String serverPubK = "";
        String clientPubK = "";
        
        try (BufferedReader reader = new BufferedReader(new FileReader(DATASET_FILE))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] data = line.split(",");
                String storedUsername = data[0].trim();
                String storedPublicKeyClient = data[2].trim();
                String storedPublicKeyServer = data[2].trim();
                

                // Check username match
                if (storedUsername.equals(clientId)) {
                    clientPubK = storedPublicKeyClient;
                }

                if (storedUsername.equals(serverId)) {
                    serverPubK = storedPublicKeyServer;
                }
            }
        } catch (IOException e) {
            System.err.println("Error during rsa retrieval: " + e.getMessage());
            
        }


        try {
            String serverCryptedSessionKey = encryptLargeDataWithRSA(createdTicket.getEncryptedSessionKey(), serverPubK);
            String doubleCryptedSessionKey = encryptLargeDataWithRSA(serverCryptedSessionKey, clientPubK);
            createdTicket.setrsaSessionKey(doubleCryptedSessionKey);
            System.out.println("Encrypted session key (KDC): " + createdTicket.getEncryptedSessionKey());
        } 
        catch (Exception e) {
            System.err.println("Error during rsa encryption: " + e.getMessage());
        }


        return createdTicket;
    }
}

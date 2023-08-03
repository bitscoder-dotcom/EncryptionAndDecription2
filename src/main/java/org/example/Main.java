package org.example;

import javax.swing.plaf.basic.BasicEditorPaneUI;
import java.security.SecureRandom;
import java.util.Base64;

public class Main {
    public static void main(String[] args) throws Exception {
        // Generate a random 24-byte key
        SecureRandom random = new SecureRandom();
        byte[] key = new byte[24];
        random.nextBytes(key);
        String encodedKey = Base64.getEncoder().encodeToString(key);
        System.out.println("Generated key: "+ encodedKey);

        // Encrypt a message
        String message = "Hello, Victor!";
        String encryptedMessase = AESExample.encrypt(encodedKey, message);
        System.out.println("Encrypted message: "+ encryptedMessase);

        // Decrypt the encypted message
        String decryptedMessage = AESExample.decrypt(encodedKey, encryptedMessase);
        System.out.println("Decrypted message: "+ decryptedMessage);
    }
}
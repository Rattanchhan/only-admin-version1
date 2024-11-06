package com.kiloit.onlyadmin.security.JWT;

import org.springframework.stereotype.Component;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

@Component
public class TokenConfig {

    public KeyPair getKeyPair(String PRIVATE_KEY_FILE,String PUBLIC_KEY_FILE) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        File privateKeyFile = new File(PRIVATE_KEY_FILE);
        File publicKeyFile = new File(PUBLIC_KEY_FILE);

        if (privateKeyFile.exists() && publicKeyFile.exists()) {
            return loadKeyPair(privateKeyFile, publicKeyFile);
        } else {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            saveKeyPair(keyPair, privateKeyFile, publicKeyFile);
            return keyPair;
        }
    }
    private KeyPair loadKeyPair(File privateKeyFile, File publicKeyFile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] privateKeyBytes = readFile(privateKeyFile);
        byte[] publicKeyBytes = readFile(publicKeyFile);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);

        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        return new KeyPair(publicKey, privateKey);
    }

   private void saveKeyPair(KeyPair keyPair, File privateKeyFile, File publicKeyFile) throws IOException {
        writeFile(privateKeyFile, keyPair.getPrivate().getEncoded());
        writeFile(publicKeyFile, keyPair.getPublic().getEncoded());
    }

    private byte[] readFile(File file) throws IOException {
        try (FileInputStream fis = new FileInputStream(file)) {
            return fis.readAllBytes();
        }
    }
    private void writeFile(File file, byte[] data) throws IOException {
        Path filePath = file.toPath();
        Path parentDir = filePath.getParent();

        if (parentDir != null && !Files.exists(parentDir)) {
            System.out.println("Creating directories for path: " + parentDir);
            Files.createDirectories(parentDir);
        }
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(data);
            fos.flush();
            System.out.println("File written successfully: " + file.getAbsolutePath());
        } catch (IOException e) {
            System.err.println("Error writing file: " + file.getAbsolutePath() + " - " + e.getMessage());
            throw new IOException("Failed to write data to file: " + file.getAbsolutePath(), e);
        }
    }

}

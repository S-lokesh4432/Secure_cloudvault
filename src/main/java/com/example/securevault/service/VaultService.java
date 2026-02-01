package com.example.securevault.service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

@Service
public class VaultService {

    private static final Path VAULT_DIR = Paths.get("vault");
    private static final Path RSA_PRIV = VAULT_DIR.resolve("rsa_private.key");
    private static final Path RSA_PUB  = VAULT_DIR.resolve("rsa_public.key");

    private static final DateTimeFormatter FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm");

    // ================= DATA HOLDER =================
    public static class VaultFile {
        public byte[] data;
        public String filename;

        public VaultFile(byte[] data, String filename) {
            this.data = data;
            this.filename = filename;
        }
    }

    // ================= UPLOAD =================
    public String lockFile(MultipartFile file, String unlockTime) throws Exception {

        Files.createDirectories(VAULT_DIR);

        LocalDateTime unlock = LocalDateTime.parse(unlockTime, FORMAT);
        if (!unlock.isAfter(LocalDateTime.now())) {
            throw new IllegalArgumentException("Unlock time must be in the future");
        }

        ensureRSAKeys();

        String fileId = UUID.randomUUID().toString();
        Path fileDir = VAULT_DIR.resolve(fileId);
        Files.createDirectories(fileDir);

        Path ENC_FILE = fileDir.resolve("data.enc");
        Path ENC_KEY  = fileDir.resolve("aes.key.enc");
        Path META     = fileDir.resolve("meta.txt");

        byte[] data = file.getBytes();

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey aesKey = kg.generateKey();

        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        Files.write(ENC_FILE, aesCipher.doFinal(data));

        PublicKey pub = loadPublicKey();
        Cipher rsa = Cipher.getInstance("RSA");
        rsa.init(Cipher.ENCRYPT_MODE, pub);
        Files.write(ENC_KEY, rsa.doFinal(aesKey.getEncoded()));

        Files.writeString(
                META,
                unlock.toString() + "\n" + file.getOriginalFilename()
        );

        return fileId;
    }

    // ================= DOWNLOAD =================
    public VaultFile accessVault(String fileId) throws Exception {

        Path fileDir = VAULT_DIR.resolve(fileId);
        Path ENC_FILE = fileDir.resolve("data.enc");
        Path ENC_KEY  = fileDir.resolve("aes.key.enc");
        Path META     = fileDir.resolve("meta.txt");

        if (!Files.exists(ENC_FILE)) return null;

        String[] meta = Files.readString(META).split("\n");
        LocalDateTime unlock = LocalDateTime.parse(meta[0]);
        String filename = meta.length > 1 ? meta[1] : "file";

        if (LocalDateTime.now().isBefore(unlock)) return null;

        PrivateKey priv = loadPrivateKey();

        Cipher rsa = Cipher.getInstance("RSA");
        rsa.init(Cipher.DECRYPT_MODE, priv);
        byte[] aesKeyBytes = rsa.doFinal(Files.readAllBytes(ENC_KEY));
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

        Cipher aes = Cipher.getInstance("AES");
        aes.init(Cipher.DECRYPT_MODE, aesKey);
        byte[] decrypted = aes.doFinal(Files.readAllBytes(ENC_FILE));

        return new VaultFile(decrypted, filename);
    }

    // ================= RSA KEYS =================
    private void ensureRSAKeys() throws Exception {
        if (Files.exists(RSA_PRIV)) return;

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        Files.write(RSA_PRIV, kp.getPrivate().getEncoded());
        Files.write(RSA_PUB,  kp.getPublic().getEncoded());
    }

    private PublicKey loadPublicKey() throws Exception {
        byte[] bytes = Files.readAllBytes(RSA_PUB);
        return KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(bytes));
    }

    private PrivateKey loadPrivateKey() throws Exception {
        byte[] bytes = Files.readAllBytes(RSA_PRIV);
        return KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(bytes));
    }
}

package com.malkeith.pgpUtils;

import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.pgpainless.PGPainless;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

public class Main {

    public  static void generateKeys() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        PGPSecretKeyRing secretKey = PGPainless.generateKeyRing()
                .modernKeyRing("Foo Bar <foo@bar.loc>", "passphrase");

        var armoredPrivateKey = PGPainless.asciiArmor(secretKey);
        System.out.println(armoredPrivateKey);

        PGPPublicKeyRing certificate = PGPainless.extractCertificate(secretKey);

        String asciiArmored = PGPainless.asciiArmor(certificate);
        System.out.println(asciiArmored);
    }

    public static void main(String[] args) throws PGPException, IOException {
        PgpEncryptionUtil pgpEncryptionUtil = PgpEncryptionUtil.builder()
                .armor(true)
                .compressionAlgorithm(CompressionAlgorithmTags.BZIP2)
                .symmetricKeyAlgorithm(SymmetricKeyAlgorithmTags.AES_256)
                .withIntegrityCheck(true)
                .build();

        var privateKey = Files.readString(Path.of("files/privateKey"));
        var publicKey = Files.readString(Path.of("files/publicKey"));

        var fileBytes = Files.readAllBytes(Path.of("files/fileInput.txt"));
        var fileOutputEncrypted = Path.of("files/fileOutPutEncrypted.txt");
        var outputPathDecrypted = Path.of("files/fileOutPutDecrypted.txt");

        byte[] encryptedBytes = pgpEncryptionUtil.encrypt(fileBytes, publicKey);
        System.out.println(new String(encryptedBytes));
        Files.createFile(fileOutputEncrypted);
        Files.write(fileOutputEncrypted, encryptedBytes, StandardOpenOption.WRITE);


        PgpDecryptionUtil pgpDecryptionUtil = new PgpDecryptionUtil(privateKey, "passphrase");
        byte[] decryptedBytes = pgpDecryptionUtil.decrypt(encryptedBytes);
        Files.createFile(outputPathDecrypted);
        Files.write(outputPathDecrypted, decryptedBytes, StandardOpenOption.WRITE);

    }
}

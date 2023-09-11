package com.malkeith.pgpUtils;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.MessageMetadata;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.key.generation.type.rsa.RsaLength;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.passphrase_provider.SecretKeyPassphraseProvider;
import org.pgpainless.policy.Policy;
import org.pgpainless.util.Passphrase;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;

public class NewMain {
    public static void main(String[] args) throws IOException, PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        var publicKey = Files.readString(Path.of("files/publicKey"));

        PGPPublicKeyRing certificate = PGPainless.readKeyRing().publicKeyRing(publicKey);


        String mensagem = "Esta é a mensagem que você deseja criptografar.";

        InputStream plaintext =  new ByteArrayInputStream(mensagem.getBytes(StandardCharsets.UTF_8));

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
                .onOutputStream(outputStream)
                .withOptions(
                        ProducerOptions.signAndEncrypt(
                                new EncryptionOptions()
                                        .addRecipient(certificate)
                                        .overrideEncryptionAlgorithm(SymmetricKeyAlgorithm.AES_192),
                                new SigningOptions()
                                        .overrideHashAlgorithm(HashAlgorithm.SHA256)
                        ).setAsciiArmor(true) // Ascii armor or not
                );

        Streams.pipeAll(plaintext, encryptionStream); // pipe the data through
        encryptionStream.close(); // important! Close the stream to finish encryption/signing

        byte[] mensagemCriptografada = outputStream.toByteArray();

        System.out.println(new String(mensagemCriptografada));


        //--------------------------------------------------------------------

        var privateKeyString = Files.readString(Path.of("files/privateKey"));

        PGPSecretKeyRing secretKey = PGPainless.readKeyRing()
                .secretKeyRing(privateKeyString);

        InputStream plaintextDecrypt = new ByteArrayInputStream( mensagemCriptografada );
        InputStream detachedSignature = Files.newInputStream(Path.of("files/privateKey"));

        var options = new ConsumerOptions();
        options = options.addDecryptionPassphrase(Passphrase.fromPassword("passphrase"));
        options = options.addDecryptionKey(secretKey);

        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(plaintextDecrypt)
                .withOptions(options);

        ByteArrayOutputStream outputStreamDecrypt = new ByteArrayOutputStream();

        Streams.pipeAll(decryptionStream, outputStreamDecrypt);
        decryptionStream.close();

        byte[] mensagemDescriptografada = outputStreamDecrypt.toByteArray();

        System.out.println(new String(mensagemDescriptografada));
    }
}

package org.encryption;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.encryption.security.PGPEncryption;
import org.encryption.security.option.EncryptionOptions;
import org.encryption.util.PGPKeyUtils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Scanner;

/**
 * Hello world!
 */
public class App {

//    public static void main(String[] args) throws IOException {
//        System.out.println("Input text to encrypt: ");
//        String raw = sc.nextLine();
//        long startEncrypt = System.currentTimeMillis();
//        PGPPublicKeyRing shentonPublicKey = PGPKeyUtils.readPublicKeyRing(Files.newInputStream(Paths.get("D:\\keys\\shenton_pub.asc")));
//        PGPSecretKeyRing o2SignPrivateKey = PGPKeyUtils.readSecretKeyRing(Files.newInputStream(Paths.get("D:\\keys\\o2_pri.asc")));
//
//
//        InputStream textStream = new ByteArrayInputStream(raw.getBytes(StandardCharsets.UTF_8));
//        ProducerOptions options =
//                ProducerOptions.signAndEncrypt(
//                                EncryptionOptions.get()
//                                        .addRecipient(shentonPublicKey)
//                                        .addPassphrase(Passphrase.fromPassword("shenton12345678")),
//                                SigningOptions.get()
//                                        .addSignature(PasswordBasedSecretKeyRingProtector.forKey(o2SignPrivateKey, Passphrase.fromPassword("o212345678")), o2SignPrivateKey))
//                        .setAsciiArmor(true);
//
////        ProducerOptions options =
////                ProducerOptions.encrypt(
////                                EncryptionOptions.get()
////                                        .addRecipient(shentonPublicKey)
////                                        .addPassphrase(Passphrase.fromPassword("shenton12345678")))
////                        .setAsciiArmor(true);
//
//        OutputStream outputStream = new ByteArrayOutputStream();
//
//        getEncryptOut(textStream, outputStream, options);
//        System.out.println("result");
//        String encryptedMsg = outputStream.toString();
//        System.out.println(encryptedMsg);
//        System.out.println("Take " + (System.currentTimeMillis() - startEncrypt) + "ms to encrypt");
//        System.out.println("----------------------------------");
//        System.out.println("decryted");
//
//        PGPPublicKeyRing o2VerifyPublicKey = PGPainless.readKeyRing().publicKeyRing(Files.newInputStream(Paths.get("D:\\keys\\o2_pub.asc")));
//        long start = System.currentTimeMillis();
//        PGPSecretKeyRing shentonPrivateKey = PGPainless.readKeyRing().secretKeyRing(Files.newInputStream(Paths.get("D:\\keys\\shenton_pri.asc")));
//
//        ConsumerOptions consumerOptions =
//                ConsumerOptions.get()
//                        .setIgnoreMDCErrors(true)
//                        .addDecryptionKey(shentonPrivateKey, PasswordBasedSecretKeyRingProtector.forKey(shentonPrivateKey, Passphrase.fromPassword("shenton12345678")))
//                        .addVerificationCert(o2VerifyPublicKey);
//        OutputStream out = new ByteArrayOutputStream();
//        getDecryptOut(new ByteArrayInputStream(encryptedMsg.getBytes(StandardCharsets.UTF_8)), out, consumerOptions);
//
//        String decryptedMsg = out.toString();
//        System.out.println(decryptedMsg);
//        System.out.println("Take " + (System.currentTimeMillis() - start) + "ms to decrypt");
//
//    }
//
//
//    private static void getEncryptOut(InputStream textStream, OutputStream out, ProducerOptions options) {
//        try (EncryptionStream stream = PGPainless.encryptAndOrSign().onOutputStream(out).withOptions(options)) {
//            Streams.pipeAll(textStream, stream);
//        } catch (Exception e) {
//            throw new RuntimeException(e);
//        }
//    }
//
//    private static void getDecryptOut(InputStream textStream, OutputStream out, ConsumerOptions options) {
//        try (DecryptionStream stream = PGPainless.decryptAndOrVerify().onInputStream(textStream).withOptions(options)) {
//            Streams.pipeAll(stream, out);
//        } catch (Exception e) {
//            throw new RuntimeException(e);
//        }
//    }

    public static void main(String[] args) throws IOException {
        String raw = "ahihi";

        long startTime = System.currentTimeMillis();
        PGPPublicKeyRing shentonPublicKey = PGPKeyUtils.readPublicKeyRing(Files.newInputStream(Paths.get("C:\\Users\\congc\\Downloads\\keys\\shenton_pub.asc")));
        System.out.println("Read public key time = " + (System.currentTimeMillis() - startTime) + "ms");
        startTime = System.currentTimeMillis();
        PGPSecretKeyRing o2SignPrivateKey = PGPKeyUtils.readSecretKeyRing(Files.newInputStream(Paths.get("C:\\Users\\congc\\Downloads\\keys\\o2_pri.asc")));
        System.out.println("Read private key time = " + (System.currentTimeMillis() - startTime) + "ms");
        startTime = System.currentTimeMillis();

        EncryptionOptions options =
                EncryptionOptions.get()
                        .withEncryptionKey(shentonPublicKey)
                        .addSignatureKey(o2SignPrivateKey, "o212345678".toCharArray())
                        .setVersion("CongNT33 V1")
                        .setComment("O2 new")
                ;

        String encryptedStr = PGPEncryption.encrypt(raw, options);
        System.out.println("Encrypted");
        System.out.println(encryptedStr);
        System.out.println("Encrypt time = " + (System.currentTimeMillis() - startTime) + "ms");
    }
}
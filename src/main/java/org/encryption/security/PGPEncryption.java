package org.encryption.security;

import org.apache.commons.collections4.CollectionUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.io.Streams;
import org.encryption.security.option.EncryptionOptions;
import org.encryption.security.stream.SignatureGenerationStream;
import org.encryption.util.SignatureUtils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Date;
import java.util.List;

public class PGPEncryption {

    private final EncryptionOptions options;

    public PGPEncryption(EncryptionOptions options) {
        this.options = options;
    }

    public static String encrypt(String raw, EncryptionOptions options) {
        try (InputStream rawInputStream = new ByteArrayInputStream(raw.getBytes(StandardCharsets.UTF_8));
             ByteArrayOutputStream encryptedOutputStream = new ByteArrayOutputStream()) {
            new PGPEncryption(options).encrypt(rawInputStream, encryptedOutputStream, encryptedOutputStream.size());
            return encryptedOutputStream.toString(StandardCharsets.UTF_8.name());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void encrypt(InputStream rawInputStream, OutputStream encryptedOutputStream, int length) throws PGPException, IOException {

        //preparer armor
        encryptedOutputStream =
                ArmoredOutputStream.builder()
                        .setComment(options.getComment())
                        .setVersion(options.getVersion())
                        .build(encryptedOutputStream);

        PGPDataEncryptorBuilder dataEncryptorBuilder =
                new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                        .setSecureRandom(new SecureRandom());
        dataEncryptorBuilder.setWithIntegrityPacket(true);

        //prepare encryption
        PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(dataEncryptorBuilder);
        encryptedDataGenerator.addMethod(
                new BcPublicKeyKeyEncryptionMethodGenerator(options.getEncryptionKey().getKey().getPublicKey())
                        .setSecureRandom(new SecureRandom()));
        encryptedOutputStream = encryptedDataGenerator.open(encryptedOutputStream, length);

        //prepare compression
        PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
        encryptedOutputStream = new BCPGOutputStream(compressedDataGenerator.open(encryptedOutputStream));

        //prepareOnePassSignature
        List<PGPKeyBuilder<PGPSecretKeyRing>> pgpKeyBuilders = options.getSignatureKeys();
        boolean isAddedSignature = CollectionUtils.isNotEmpty(pgpKeyBuilders);
        for (PGPKeyBuilder<PGPSecretKeyRing> keyBuilder : pgpKeyBuilders) {
            PGPSignatureGenerator signatureGenerator = SignatureUtils.getSignature(keyBuilder);
            signatureGenerator.generateOnePassVersion(false).encode(encryptedOutputStream);
        }

        //prepare literal data
        PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
//        encryptedOutputStream = literalDataGenerator.open(encryptedOutputStream, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, length, new Date());

        try (OutputStream out = literalDataGenerator.open(encryptedOutputStream, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, length, new Date())) {
            Streams.pipeAll(rawInputStream, out);
            encryptedOutputStream = out;
        }

        // sign msg
        if (isAddedSignature) {
            long time1 = System.currentTimeMillis();
            encryptedOutputStream = new SignatureGenerationStream(encryptedOutputStream, options);
            System.out.println("Check add signature time = " + (System.currentTimeMillis() - time1) + "ms");
        }

//        Streams.pipeAll(rawInputStream, encryptedOutputStream);
    }

}

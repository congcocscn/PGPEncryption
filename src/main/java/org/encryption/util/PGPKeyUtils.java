package org.encryption.util;

import lombok.Getter;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPMarker;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;
import org.encryption.security.PGPKeyBuilder;

import java.io.IOException;
import java.io.InputStream;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;

public class PGPKeyUtils {

    @Getter
    private static final Provider bouncyCastleProvider = new BouncyCastleProvider();

    static {
        Security.addProvider(bouncyCastleProvider);
    }
    private static final int maxCount = 10000;
    public static PGPPublicKeyRing readPublicKeyRing(InputStream armoredInputStream) throws IOException {
        long startTime = System.currentTimeMillis();
        InputStream decoderStream = PGPUtil.getDecoderStream(armoredInputStream);
        System.out.println("Get decoder stream time = " + (System.currentTimeMillis() - startTime) + "ms");
        startTime = System.currentTimeMillis();
//        PGPObjectFactory objectFactory =
//                new PGPObjectFactory(
//                        decoderStream,
//                        new BcKeyFingerprintCalculator());
        PGPPublicKeyRing publicKeys = new PGPPublicKeyRing(decoderStream, new BcKeyFingerprintCalculator());
        System.out.println("Read key time public " + (System.currentTimeMillis() - startTime) + "ms");
        return publicKeys;

//        int index = 0;
//        while (index < maxCount) {
//            System.out.println("next time " + index);
//            Object nextValue = objectFactory.nextObject();
//            if (Objects.isNull(nextValue)) {
//                throw new RuntimeException("Invalid Public Key!");
//            }
//            if(nextValue instanceof PGPMarker) {
//                continue;
//            }
//            if (nextValue instanceof PGPPublicKeyRing) {
//                PGPPublicKeyRing publicKeyRing = (PGPPublicKeyRing) nextValue;
//                checkValidKeyDate(publicKeyRing);
//                return publicKeyRing;
//            }
//            index++;
//        }
//        throw new RuntimeException("[PGPKeyUtils.readPublicKeyRing] Not found PGPPublicKeyRing in stream!");
    }

    public static PGPSecretKeyRing readSecretKeyRing(InputStream armoredInputStream) throws IOException {
        InputStream decoderStream = PGPUtil.getDecoderStream(armoredInputStream);
        PGPObjectFactory objectFactory =
                new PGPObjectFactory(
                        decoderStream,
                        new JcaKeyFingerprintCalculator()
                                .setProvider(bouncyCastleProvider));

        int index = 0;
        while (index < maxCount) {
            Object nextValue = objectFactory.nextObject();
            if (Objects.isNull(nextValue)) {
                throw new RuntimeException("Invalid Secret Key!");
            }
            if(nextValue instanceof PGPMarker) {
                continue;
            }
            if (nextValue instanceof PGPSecretKeyRing) {
                Streams.drain(decoderStream);
                PGPSecretKeyRing secretKeyRing = (PGPSecretKeyRing) nextValue;
                checkValidKeyDate(secretKeyRing);
                return secretKeyRing;
            }
            index++;
        }
        throw new RuntimeException("[PGPKeyUtils.readSecretKeyRing] Not found PGPSecretKeyRing in stream!");
    }

    public static PGPPrivateKey unlockSecretKey(PGPKeyBuilder<PGPSecretKeyRing> keyBuilder) {
        PGPSecretKey secretKey = keyBuilder.getKey().getSecretKey();
        char[] passphrase = keyBuilder.getPassphrase();

        try {
            PBESecretKeyDecryptor secretKeyDecryptor =
                    new JcePBESecretKeyDecryptorBuilder()
                            .setProvider(bouncyCastleProvider)
                            .build(passphrase);
            return secretKey.extractPrivateKey(secretKeyDecryptor);
        } catch (PGPException e) {
            throw new RuntimeException("Invalid passphrase!");
        }
    }

    public static List<String> getUserIds(PGPPublicKey key) {
        List<String> userIds = new ArrayList<>();
        Iterator<byte[]> it = key.getRawUserIDs();
        while (it.hasNext()) {
            byte[] rawUserId = it.next();
            userIds.add(Strings.fromUTF8ByteArray(rawUserId));
        }
        return userIds;
    }

    private static void checkValidKeyDate(PGPKeyRing keyRing) {
        //TODO: validate key effectiveDate
    }
}

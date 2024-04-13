package org.encryption.util;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPMarker;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.util.io.Streams;

import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

public class PGPKeyUtils {
    private static final int maxCount = 10000;
    public static PGPPublicKeyRing readPublicKeyRing(ArmoredInputStream armoredInputStream) throws IOException {
        InputStream decoderStream = PGPUtil.getDecoderStream(armoredInputStream);
        PGPObjectFactory objectFactory =
                new PGPObjectFactory(
                        decoderStream,
                        new JcaKeyFingerprintCalculator()
                                .setProvider(BouncyCastleProvider.PROVIDER_NAME));

        int index = 0;
        while (index < maxCount) {
            Object nextValue = objectFactory.nextObject();
            if (Objects.isNull(nextValue)) {
                return null;
            }
            if(nextValue instanceof PGPMarker) {
                continue;
            }
            if (nextValue instanceof PGPPublicKeyRing) {
                return (PGPPublicKeyRing) nextValue;
            }
            index++;
        }
        throw new RuntimeException("[PGPKeyUtils.readPublicKeyRing] Not found PGPPublicKeyRing in stream!");
    }

    public static PGPSecretKeyRing readSecretKeyRing(ArmoredInputStream armoredInputStream) throws IOException {
        InputStream decoderStream = PGPUtil.getDecoderStream(armoredInputStream);
        PGPObjectFactory objectFactory =
                new PGPObjectFactory(
                        decoderStream,
                        new JcaKeyFingerprintCalculator()
                                .setProvider(BouncyCastleProvider.PROVIDER_NAME));

        int index = 0;
        while (index < maxCount) {
            Object nextValue = objectFactory.nextObject();
            if (Objects.isNull(nextValue)) {
                return null;
            }
            if(nextValue instanceof PGPMarker) {
                continue;
            }
            if (nextValue instanceof PGPSecretKeyRing) {
                Streams.drain(decoderStream);
                return (PGPSecretKeyRing) nextValue;
            }
            index++;
        }
        throw new RuntimeException("[PGPKeyUtils.readSecretKeyRing] Not found PGPSecretKeyRing in stream!");
    }
}

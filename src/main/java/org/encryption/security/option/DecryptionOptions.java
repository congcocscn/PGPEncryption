package org.encryption.security.option;

import lombok.Getter;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.encryption.security.PGPKeyBuilder;

import java.util.ArrayList;
import java.util.List;

@Getter
public final class DecryptionOptions {

    private PGPKeyBuilder<PGPSecretKeyRing> decryptionKey;
    private final List<PGPKeyBuilder<PGPPublicKeyRing>> verificationKeys = new ArrayList<>();

    public static DecryptionOptions get() {
        return new DecryptionOptions();
    }

    public DecryptionOptions withDecryptionKey(PGPSecretKeyRing secretKey) {
        this.decryptionKey = new PGPKeyBuilder<>(secretKey);
        return this;
    }

    public DecryptionOptions withDecryptionKey(PGPSecretKeyRing secretKey, char[] passphrase) {
        this.decryptionKey = new PGPKeyBuilder<>(secretKey, passphrase);
        return this;
    }

    public DecryptionOptions addVerificationKey(PGPPublicKeyRing verificationKey) {
        this.verificationKeys.add(new PGPKeyBuilder<>(verificationKey));
        return this;
    }
}

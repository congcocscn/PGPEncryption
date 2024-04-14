package org.encryption.security.option;

import lombok.Getter;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.encryption.security.PGPKeyBuilder;

import java.util.ArrayList;
import java.util.List;

@Getter
public class EncryptionOptions {

    private PGPKeyBuilder<PGPPublicKeyRing> encryptionKey;
    private final List<PGPKeyBuilder<PGPSecretKeyRing>> signatureKeys = new ArrayList<>();
    private String comment;
    private String version;

    public static EncryptionOptions get() {
        return new EncryptionOptions();
    }

    public EncryptionOptions withEncryptionKey(PGPPublicKeyRing publicKey) {
        this.encryptionKey = new PGPKeyBuilder<>(publicKey);
        return this;
    }

    public EncryptionOptions addSignatureKey(PGPSecretKeyRing signatureKey) {
        this.signatureKeys.add(new PGPKeyBuilder<>(signatureKey));
        return this;
    }

    public EncryptionOptions addSignatureKey(PGPSecretKeyRing signatureKey, char[] passphrase) {
        this.signatureKeys.add(new PGPKeyBuilder<>(signatureKey, passphrase));
        return this;
    }

    public EncryptionOptions setComment(String comment) {
        this.comment = comment;
        return this;
    }

    public EncryptionOptions setVersion(String version) {
        this.version = version;
        return this;
    }
}

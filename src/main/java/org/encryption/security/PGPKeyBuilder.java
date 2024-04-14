package org.encryption.security;

import lombok.Getter;
import org.bouncycastle.openpgp.PGPKeyRing;

@Getter
public class PGPKeyBuilder<T extends PGPKeyRing> {
    private final T key;
    private char[] passphrase;

    public PGPKeyBuilder(T key) {
        this.key = key;
    }

    public PGPKeyBuilder(T key, char[] passphrase) {
        this.key = key;
        this.passphrase = passphrase;
    }
}

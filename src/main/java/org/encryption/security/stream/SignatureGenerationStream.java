package org.encryption.security.stream;

import org.apache.commons.collections4.CollectionUtils;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.encryption.security.PGPKeyBuilder;
import org.encryption.security.option.EncryptionOptions;
import org.encryption.util.SignatureUtils;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Objects;

public class SignatureGenerationStream extends OutputStream {

    private final OutputStream wrapped;
    private final EncryptionOptions options;

    public SignatureGenerationStream(OutputStream wrapped, EncryptionOptions encryptionOptions) {
        this.wrapped = wrapped;
        this.options = encryptionOptions;
    }

    @Override
    public void write(int b) throws IOException {
        wrapped.write(b);
        if (Objects.isNull(options) || CollectionUtils.isEmpty(options.getSignatureKeys())) {
            return;
        }

        for (PGPKeyBuilder<PGPSecretKeyRing> signatureKey : options.getSignatureKeys()) {
            try {
                PGPSignatureGenerator signatureGenerator = SignatureUtils.getSignature(signatureKey);
                byte asByte = (byte) (b & 0xff);
                signatureGenerator.update(asByte);
            } catch (PGPException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @Override
    public void write(@Nonnull byte[] buffer) throws IOException {
        write(buffer, 0, buffer.length);
    }

    @Override
    public void write(@Nonnull byte[] buffer, int off, int len) throws IOException {
        wrapped.write(buffer, 0, len);
        if (Objects.isNull(options) || CollectionUtils.isEmpty(options.getSignatureKeys())) {
            return;
        }

        for (PGPKeyBuilder<PGPSecretKeyRing> signatureKey : options.getSignatureKeys()) {
            try {
                PGPSignatureGenerator signatureGenerator = SignatureUtils.getSignature(signatureKey);
                signatureGenerator.update(buffer, 0, len);
            } catch (PGPException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @Override
    public void close() throws IOException {
        wrapped.close();
    }
}
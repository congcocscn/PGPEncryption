package org.encryption.util;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.encryption.security.PGPKeyBuilder;

public class SignatureUtils {
    public static  PGPSignatureGenerator getSignature(PGPKeyBuilder<PGPSecretKeyRing> keyBuilder) throws PGPException {
        PGPContentSignerBuilder contentSignerBuilder =
                new BcPGPContentSignerBuilder(PublicKeyAlgorithmTags.RSA_SIGN, HashAlgorithmTags.SHA256);
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(contentSignerBuilder);
        signatureGenerator.init(PGPSignature.SUBKEY_BINDING, PGPKeyUtils.unlockSecretKey(keyBuilder));
        return signatureGenerator;
    }
}

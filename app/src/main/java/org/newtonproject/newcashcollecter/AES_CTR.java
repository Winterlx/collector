package org.newtonproject.newcashcollecter;

import org.bouncycastle.crypto.generators.SCrypt;
import org.web3j.crypto.CipherException;
import org.web3j.crypto.ECKeyPair;
import org.web3j.utils.Numeric;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class AES_CTR {

    private static final int SCRYPT_DKLEN = 32;
    private static final int SCRYPT_N = 4096;
    private static final int SCRYPT_P = 6;
    private static final int SCRYPT_R = 8;
    private static final int SCRYPT_N_262144 = 262144;
    private static final int SCRYPT_P_1 = 1 ;

    public AES_CTR() {
    }

    private static byte[] generateDerivedScryptKey(
            byte[] password, byte[] salt) {
        return SCrypt.generate(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_DKLEN);
    }

    private static byte[] generateDerivedScryptKey(
            byte[] password, byte[] salt,int scrypt_n) {
        return SCrypt.generate(password, salt, SCRYPT_N_262144, SCRYPT_R, SCRYPT_P_1, SCRYPT_DKLEN);
    }

    // TODO: 2019/4/26 mode 改一下就好了
    public static byte[] DECRYPT(
            byte[] iv, byte[] encryptKey, byte[] encryptedText) throws CipherException {

        try {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            //encryptKey 32bits
            //iv 16bits
            SecretKeySpec secretKeySpec = new SecretKeySpec(encryptKey, "AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
            return cipher.doFinal(encryptedText);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException
                | InvalidAlgorithmParameterException | InvalidKeyException
                | BadPaddingException | IllegalBlockSizeException e) {
            throw new CipherException("Error performing cipher operation", e);
        }
    }

    public static byte[] ENCRYPT(byte[] iv, byte[] encryptKey, byte[] text) throws CipherException {
        try {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            //encryptKey 32bits
            //iv 16bits
            SecretKeySpec secretKeySpec = new SecretKeySpec(encryptKey, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            return cipher.doFinal(text);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException
                | InvalidAlgorithmParameterException | InvalidKeyException
                | BadPaddingException | IllegalBlockSizeException e) {
            throw new CipherException("Error performing cipher operation", e);
        }

    }

    public static byte[] randomHexString(int i) {
        //生成十六进制随机数
        try {
            SecureRandom random = SecureRandom.getInstanceStrong();
            byte[] values = new byte[i];
            random.nextBytes(values);
            return values;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

}

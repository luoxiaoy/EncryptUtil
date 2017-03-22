package com.ly.encrydemo;

import android.text.TextUtils;
import android.util.Base64;

import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by ly on 2017/3/21.
 * 加解密工具类 AES DES DES3
 */
public class EncryUtils {

    /**
     * 生成密钥
     * @param keysize
     * @param encryption AES DES
     * @return
     */
    public static byte[] initKey(int keysize,String encryption) {
        KeyGenerator keyGen = null;
        try {
            keyGen = KeyGenerator.getInstance(encryption);
            keyGen.init(keysize);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        SecretKey secretKey = keyGen.generateKey();
        return secretKey.getEncoded();
    }

    //填充方式
    //ZeroBytePadding
    //pkcs5padding
    //pkcs7padding

    /**
     * 加解密方式
     */
    enum Encryption {
        AES,   // Key length must 16/24/32 bytes   IV length must 16 bytes
        DES,   // Key、IV  8 bytes
        DES3   // Key 16 or 24 bytes.  IV  8 bytes
    }

    /**
     * 加解密模式
     */
    enum EncryptMode {
        ECB,
        CBC,
        CTR,
        OFB,
        CFB
    }

    /**
     * ECB方式加密
     * @return
     */
    private static String EcbEncrypt(String str,String key,String encryption){
        try {
            Cipher cipher = Cipher.getInstance(String.format("%s/ECB/pkcs5padding",encryption));
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getBytes("utf-8"), encryption));
            byte[] bytes = cipher.doFinal(str.getBytes("utf-8"));
            return Base64.encodeToString(bytes, Base64.NO_WRAP);   //注 Base64.DEFAULT 加密后有\n
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * ECB方式解密
     * @return
     */
    private static String EcbDecrypt(String str,String key,String encryption){
        try {
            Cipher cipher = Cipher.getInstance(String.format("%s/ECB/PKCS5Padding",encryption));
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key.getBytes("utf-8"), encryption));
            byte[] bytes = cipher.doFinal(Base64.decode(str.getBytes("utf-8"), Base64.NO_WRAP));
            return new String(bytes, "utf-8");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 先AES 加密，再通过Base64加密
     * @param str   需要加密的字符串
     * @param strKey  加密的密钥key
     * @param strIv   加密的向量iv
     * @param mode    加密模式ECB
     *                 模式的填充方式的 PKCS5Padding
     *                 需要Padding的有：CBC（，PCBC也需要，本文未涉及该加密模式）、ECB。
                       不需要Padding的有：CFB、OFB、CTR
     * @return
     */
    public static String AesDesEncrypt(String str,String strKey,String strIv,Encryption encryption,EncryptMode mode){
        if (TextUtils.isEmpty(str) || TextUtils.isEmpty(strKey))
            return null;
        String strMode = null;
        String strEncryption = null;
        switch (encryption){
            case AES:
                strEncryption = "AES";
                break;
            case DES:
                strEncryption = "DES";
                break;
            case DES3:
                strEncryption = "DESede";
                break;
        }
        switch (mode){
            case ECB:
                return EcbEncrypt(str,strKey,strEncryption);
            case CBC:
                strMode = "CBC";
                break;
            case CTR:
                strMode = "CTR";
                break;
            case OFB:
                strMode = "OFB";
                break;
            case CFB:
                strMode = "CFB";
                break;
            default:
                return null;
        }
        if(TextUtils.isEmpty(strIv))
            return null;
        try {
            byte[] raw = strKey.getBytes();
            SecretKeySpec skeySpec = new SecretKeySpec(raw, strEncryption);
            Cipher cipher = Cipher.getInstance(String.format("%s/%s/PKCS5Padding",strEncryption,strMode));
            IvParameterSpec iv = new IvParameterSpec(strIv.getBytes());
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
            byte[] encryptBytes = cipher.doFinal(str.getBytes());
            return Base64.encodeToString(encryptBytes, Base64.NO_WRAP);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 先通过Base64解密，再AES 解密
     * @param str   需要解密的字符串
     * @param strKey  解密的密钥key
     * @param strIv   解密的向量iv
     * @param mode    解密模式ECB
     *                 模式的填充方式的 PKCS5Padding
     * @return
     */
    public static String AesDesDecrypt(String str,String strKey,String strIv,Encryption encryption,EncryptMode mode){
        if (TextUtils.isEmpty(str) || TextUtils.isEmpty(strKey))
            return null;
        String strMode = null;
        String strEncryption = null;
        switch (encryption){
            case AES:
                strEncryption = "AES";
                break;
            case DES:
                strEncryption = "DES";
                break;
            case DES3:
                strEncryption = "DESede";
                break;
        }
        switch (mode){
            case ECB:
                return EcbDecrypt(str,strKey,strEncryption);
            case CBC:
                strMode = "CBC";
                break;
            case CTR:
                strMode = "CTR";
                break;
            case OFB:
                strMode = "OFB";
                break;
            case CFB:
                strMode = "CFB";
                break;
            default:
                return null;
        }
        if(TextUtils.isEmpty(strIv))
            return null;
        try {
            byte[] raw = strKey.getBytes();
            SecretKeySpec skeySpec = new SecretKeySpec(raw, strEncryption);
            Cipher cipher = Cipher.getInstance(String.format("%s/%s/PKCS5Padding",strEncryption,strMode));
            IvParameterSpec iv = new IvParameterSpec(strIv.getBytes());
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            byte[] decryptBytes = cipher.doFinal(Base64.decode(str.getBytes("utf-8"), Base64.NO_WRAP));
            return new String(decryptBytes, "utf-8");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 16进制转 byte
     * @param strhex
     * @return
     */
    public static byte[] hex2byte(String strhex) {
        if (strhex == null) {
            return null;
        }
        int l = strhex.length();
        if (l % 2 == 1) {
            return null;
        }
        byte[] b = new byte[l / 2];
        for (int i = 0; i != l / 2; i++) {
            b[i] = (byte) Integer.parseInt(strhex.substring(i * 2, i * 2 + 2),
                    16);
        }
        return b;
    }


    /**
     * byte转16进制字符串
     * @param b
     * @return
     */
    public static String byte2hex(byte[] b) {
        String hs = "";
        String stmp = "";
        for (int n = 0; n < b.length; n++) {
            stmp = (java.lang.Integer.toHexString(b[n] & 0XFF));
            if (stmp.length() == 1) {
                hs = hs + "0" + stmp;
            } else {
                hs = hs + stmp;
            }
        }
        return hs.toUpperCase();
    }
}

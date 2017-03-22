package com.ly.encrydemo;

import android.util.Base64;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import static android.util.Base64.decode;

/**
 * Created by user on 2017/3/22.
 */
public class RSAUtil {

    /**
     * RSA 加密，通过公钥加密数据，密钥从文件流读取
     * @param paramStr
     * @param inputStream
     * @return
     */
    public static String EncryptDataOfPublicKey(String paramStr,InputStream inputStream){
        try {
            byte[] paramBytes = paramStr.getBytes("utf-8");
            PublicKey publicKey = getPublicKey(inputStream);

            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPADDING");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            int i = paramBytes.length;  //数据总长度
            ByteArrayOutputStream bytearrayoutputstream = new ByteArrayOutputStream();
            int len = cipher.getBlockSize();  //获取每次加密的数据长度  官方文档 https://developer.android.google.cn/reference/javax/crypto/CipherSpi.html#engineDoFinal(byte[], int, int)
            int j = 0;
            int k = 0;
            while (i - k > 0) {
                byte midBytes[];
                int l;
                if (i - k > len)
                    midBytes = cipher.doFinal(paramBytes, k, len);
                else
                    midBytes = cipher.doFinal(paramBytes, k, i - k);
                bytearrayoutputstream.write(midBytes, 0, midBytes.length);
                l = j + 1;
                k = l * len;
                j = l;
            }
            byte[] encryptData = bytearrayoutputstream.toByteArray();
            bytearrayoutputstream.close();

            String str = Base64.encodeToString(encryptData, Base64.NO_WRAP);
            return str;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * RSA 加密，通过私钥加密数据，密钥从文件流读取
     * @param paramStr
     * @param inputStream
     * @return
     */
    public static String EncryptDataOfPrivateKey(String paramStr,InputStream inputStream){
        try {
            byte[] paramBytes = paramStr.getBytes("utf-8");
            PrivateKey privateKey = getPrivateKey(inputStream);

            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPADDING");
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            int i = paramBytes.length;  //数据总长度
            ByteArrayOutputStream bytearrayoutputstream = new ByteArrayOutputStream();
            int len = cipher.getBlockSize();  //获取每次加密的数据长度  官方文档 https://developer.android.google.cn/reference/javax/crypto/CipherSpi.html#engineDoFinal(byte[], int, int)
            int j = 0;
            int k = 0;
            while (i - k > 0) {
                byte midBytes[];
                int l;
                if (i - k > len)
                    midBytes = cipher.doFinal(paramBytes, k, len);
                else
                    midBytes = cipher.doFinal(paramBytes, k, i - k);
                bytearrayoutputstream.write(midBytes, 0, midBytes.length);
                l = j + 1;
                k = l * len;
                j = l;
            }
            byte[] encryptData = bytearrayoutputstream.toByteArray();
            bytearrayoutputstream.close();

            String str = Base64.encodeToString(encryptData, Base64.NO_WRAP);
            return str;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * RSA 解密，通过公钥解密数据，密钥从文件流读取
     * @param paramStr
     * @param inputStream
     * @return
     */
    public static String DecryptDataOfPublicKey(String paramStr,InputStream inputStream){
        try {
            PublicKey publicKey = getPublicKey(inputStream);

            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPADDING");
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            byte[] paramBytes = Base64.decode(paramStr,Base64.NO_WRAP);
            int i = paramBytes.length;  //数据总长度
            ByteArrayOutputStream bytearrayoutputstream = new ByteArrayOutputStream();
            int len = 128;  //每次解密的长度，每段数据加密后长度都是128
            int j = 0;
            int k = 0;
            while (i - k > 0) {
                byte midBytes[];
                int l;
                if (i - k > len)
                    midBytes = cipher.doFinal(paramBytes, k, len);
                else
                    midBytes = cipher.doFinal(paramBytes, k, i - k);
                bytearrayoutputstream.write(midBytes, 0, midBytes.length);
                l = j + 1;
                k = l * len;
                j = l;
            }
            byte[] decryptData = bytearrayoutputstream.toByteArray();
            bytearrayoutputstream.close();

            return new String(decryptData);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    /**
     * RSA 解密，通过私钥解密数据，密钥从文件流读取
     * @param paramStr
     * @param inputStream
     * @return
     */
    public static String DecryptDataOfPrivateKey(String paramStr,InputStream inputStream){
        try {
            PrivateKey privateKey = getPrivateKey(inputStream);

            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPADDING");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] paramBytes = Base64.decode(paramStr,Base64.NO_WRAP);

//            byte[] decryptData = cipher.doFinal(paramBytes);

            int i = paramBytes.length;  //数据总长度
            ByteArrayOutputStream bytearrayoutputstream = new ByteArrayOutputStream();
            int len = 128;  //每次解密的长度，每段数据加密后长度都是128
            int j = 0;
            int k = 0;
            while (i - k > 0) {
                byte midBytes[];
                int l;
                if (i - k > len)
                    midBytes = cipher.doFinal(paramBytes, k, len);
                else
                    midBytes = cipher.doFinal(paramBytes, k, i - k);
                bytearrayoutputstream.write(midBytes, 0, midBytes.length);
                l = j + 1;
                k = l * len;
                j = l;
            }
            byte[] decryptData = bytearrayoutputstream.toByteArray();
            bytearrayoutputstream.close();

            return new String(decryptData);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 通过文件流来读取公钥
     * @param paramInputStream
     * @return
     * @throws Exception
     */
    private static PublicKey getPublicKey(InputStream paramInputStream) throws Exception {
        try {
            PublicKey localPublicKey = null;
            BufferedReader bufferedreader = new BufferedReader(new InputStreamReader(paramInputStream));
            StringBuilder stringbuilder = new StringBuilder();
            do
            {
                String s = bufferedreader.readLine();
                if(s == null)
                    break;
                if(s.charAt(0) != '-')
                {
                    stringbuilder.append(s);
                    stringbuilder.append('\r');
                }
            } while(true);
            String paramString =  stringbuilder.toString();

            byte[] arrayOfByte = decode(paramString, Base64.NO_WRAP);
            localPublicKey = (RSAPublicKey) KeyFactory
                    .getInstance("RSA").generatePublic(
                            new X509EncodedKeySpec(arrayOfByte));
            return localPublicKey;
        } catch (IOException localIOException) {
            throw new Exception("公钥数据流读取错误");
        } catch (NullPointerException localNullPointerException) {

        }catch (NoSuchAlgorithmException localNoSuchAlgorithmException) {
            throw new Exception("无此算法");
        } catch (InvalidKeySpecException localInvalidKeySpecException) {
            throw new Exception("公钥非法");
        }
        throw new Exception("公钥输入流为空");
    }

    /**
     * 通过文件流来读取私钥
     * @param paramInputStream
     * @return
     * @throws Exception
     */
    private static PrivateKey getPrivateKey(InputStream paramInputStream) throws Exception {
        try {
            BufferedReader bufferedreader = new BufferedReader(new InputStreamReader(paramInputStream));
            StringBuilder stringbuilder = new StringBuilder();
            do {
                String s = bufferedreader.readLine();
                if (s == null)
                    break;
                if (s.charAt(0) != '-') {
                    stringbuilder.append(s);
                    stringbuilder.append('\r');
                }
            } while (true);
            String paramString = stringbuilder.toString();

            byte[] buffer = decode(paramString, Base64.NO_WRAP);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(buffer);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此算法");
        } catch (InvalidKeySpecException e) {
            throw new Exception("私钥非法");
        } catch (NullPointerException e) {
            throw new Exception("私钥数据为空");
        }
    }

    /**
     * RSA 加密，通过私钥加密数据，密钥由n e生成
     * @param paramStr
     * @param modulus
     * @param exponent
     * @return
     */
    public static String EncryptDataOfPublicKey(String paramStr,String modulus, String exponent){
        try {
            byte[] paramBytes = paramStr.getBytes("utf-8");
            PublicKey publicKey = getPublicKey(modulus,exponent);
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPADDING");  //RSA/ECB/PKCS1Padding
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            int i = paramBytes.length;  //数据总长度
            ByteArrayOutputStream bytearrayoutputstream = new ByteArrayOutputStream();
            int len = cipher.getBlockSize();  //获取每次加密的数据长度  官方文档 https://developer.android.google.cn/reference/javax/crypto/CipherSpi.html#engineDoFinal(byte[], int, int)
            int j = 0;
            int k = 0;
            while (i - k > 0) {
                byte midBytes[];
                int l;
                if (i - k > len)
                    midBytes = cipher.doFinal(paramBytes, k, len);
                else
                    midBytes = cipher.doFinal(paramBytes, k, i - k);
                bytearrayoutputstream.write(midBytes, 0, midBytes.length);
                l = j + 1;
                k = l * len;
                j = l;
            }
            byte[] encryptData = bytearrayoutputstream.toByteArray();
            bytearrayoutputstream.close();

            String str = Base64.encodeToString(encryptData, Base64.NO_WRAP);
            return str;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    /**
     * RSA 解密，通过私钥解密数据，密钥由n e生成
     * @param paramStr
     * @param modulus
     * @param exponent
     * @return
     */
    public static String DecryptDataOfPrivateKey(String paramStr,String modulus, String exponent){
        try {
            PrivateKey privateKey = getPrivateKey(modulus,exponent);

            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPADDING");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] paramBytes = Base64.decode(paramStr,Base64.NO_WRAP);
            int i = paramBytes.length;  //数据总长度
            ByteArrayOutputStream bytearrayoutputstream = new ByteArrayOutputStream();
            int len = 128;  //每次解密的长度，每段数据加密后长度都是128
            int j = 0;
            int k = 0;
            while (i - k > 0) {
                byte midBytes[];
                int l;
                if (i - k > len)
                    midBytes = cipher.doFinal(paramBytes, k, len);
                else
                    midBytes = cipher.doFinal(paramBytes, k, i - k);
                bytearrayoutputstream.write(midBytes, 0, midBytes.length);
                l = j + 1;
                k = l * len;
                j = l;
            }
            byte[] decryptData = bytearrayoutputstream.toByteArray();
            bytearrayoutputstream.close();

            return new String(decryptData);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    /**
     * RSA 加密，通过私钥加密数据，密钥由n e生成
     * @param paramStr
     * @param modulus
     * @param exponent
     * @return
     */
    public static String EncryptDataOfPrivateKey(String paramStr,String modulus, String exponent){
        try {
            byte[] paramBytes = paramStr.getBytes("utf-8");
            PrivateKey privateKey = getPrivateKey(modulus,exponent);

            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPADDING");
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            int i = paramBytes.length;  //数据总长度
            ByteArrayOutputStream bytearrayoutputstream = new ByteArrayOutputStream();
            int len = cipher.getBlockSize();  //获取每次加密的数据长度  官方文档 https://developer.android.google.cn/reference/javax/crypto/CipherSpi.html#engineDoFinal(byte[], int, int)
            int j = 0;
            int k = 0;
            while (i - k > 0) {
                byte midBytes[];
                int l;
                if (i - k > len)
                    midBytes = cipher.doFinal(paramBytes, k, len);
                else
                    midBytes = cipher.doFinal(paramBytes, k, i - k);
                bytearrayoutputstream.write(midBytes, 0, midBytes.length);
                l = j + 1;
                k = l * len;
                j = l;
            }
            byte[] encryptData = bytearrayoutputstream.toByteArray();
            bytearrayoutputstream.close();

            String str = Base64.encodeToString(encryptData, Base64.NO_WRAP);
            return str;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * RSA 解密，通过公钥解密数据，密钥由n e生成
     * @param paramStr
     * @param modulus
     * @param exponent
     * @return
     */
    public static String DecryptDataOfPublicKey(String paramStr,String modulus, String exponent){
        try {
            PublicKey publicKey = getPublicKey(modulus,exponent);

            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPADDING");
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            byte[] paramBytes = Base64.decode(paramStr,Base64.NO_WRAP);

            int i = paramBytes.length;  //数据总长度
            ByteArrayOutputStream bytearrayoutputstream = new ByteArrayOutputStream();
            int len = 128;  //每次解密的长度，每段数据加密后长度都是128
            int j = 0;
            int k = 0;
            while (i - k > 0) {
                byte midBytes[];
                int l;
                if (i - k > len)
                    midBytes = cipher.doFinal(paramBytes, k, len);
                else
                    midBytes = cipher.doFinal(paramBytes, k, i - k);
                bytearrayoutputstream.write(midBytes, 0, midBytes.length);
                l = j + 1;
                k = l * len;
                j = l;
            }
            byte[] decryptData = bytearrayoutputstream.toByteArray();
            bytearrayoutputstream.close();

            return new String(decryptData);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    /**
     * 公钥由n e生成
     * @param modulus
     * @param exponent
     * @return
     */
    private static PublicKey getPublicKey(String modulus, String exponent) throws Exception {
        return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(new BigInteger(modulus, 16), new BigInteger(exponent, 16)));
    }
    /**
     * 私钥由n e生成
     * @param modulus
     * @param exponent
     * @return
     */
    private static PrivateKey getPrivateKey(String modulus, String exponent) throws Exception {
        return KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateKeySpec(new BigInteger(modulus, 16), new BigInteger(exponent, 16)));
    }
}

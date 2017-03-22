package com.ly.encrydemo;

import android.content.Context;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;


public class MainActivity extends AppCompatActivity {

    /**
     * AES 加密的密钥key 和向量 iv
     * Key 长度 16/24/32 bytes   IV 长度 16 bytes
     */
    private String AES_KEY = "adjiganaadjigana";
    private String AES_IV = "adjiganaadjigana";


    /**
     * DES 加密的密钥key 和向量 iv
     * 密钥和向量长度 必须为8
     */
    private String DES_KEY = "adjigana";
    private String DES_IV = "adjigana";

    /**
     * DES3 加密的密钥key 和向量 iv
     * key 长度 16 or 24 bytes. 必须为8
     */
    private String DES3_KEY = "asdjdsgnasgeaeesiaskdfje";
    private String DES3_IV = "adjigana";

    /**
     * 测试原数据  AES  DES  DES3
     */
    private String strTestData = "MainActivity";

    private Context mContext;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        mContext = this;

        /**
         * AES 加解密
         */
        Log.e("test","-----------  :" + "加密结果 " + "                  解密结果 ");
        //Key length must 128/192/256 bits   IV length must 16 bytes
        String AesEncryptECB = EncryUtils.AesDesEncrypt(strTestData,AES_KEY,"",EncryUtils.Encryption.AES, EncryUtils.EncryptMode.ECB);
        Log.e("test","AES ----- ECB:"+ AesEncryptECB +  "   " + EncryUtils.AesDesDecrypt(AesEncryptECB,AES_KEY,"", EncryUtils.Encryption.AES,EncryUtils.EncryptMode.ECB));

        String AesEncryptCBC = EncryUtils.AesDesEncrypt(strTestData,AES_KEY,AES_IV,EncryUtils.Encryption.AES, EncryUtils.EncryptMode.CBC);
        Log.e("test","AES ----- CBC:"+ AesEncryptCBC +  "   " + EncryUtils.AesDesDecrypt(AesEncryptCBC,AES_KEY,AES_IV,EncryUtils.Encryption.AES, EncryUtils.EncryptMode.CBC));

        String AesEncryptCFB = EncryUtils.AesDesEncrypt(strTestData,AES_KEY,AES_IV,EncryUtils.Encryption.AES, EncryUtils.EncryptMode.CFB);
        Log.e("test","AES ----- CFB:"+ AesEncryptCFB +  "   " + EncryUtils.AesDesDecrypt(AesEncryptCFB,AES_KEY,AES_IV,EncryUtils.Encryption.AES, EncryUtils.EncryptMode.CFB));

        String AesEncryptCTR = EncryUtils.AesDesEncrypt(strTestData,AES_KEY,AES_IV,EncryUtils.Encryption.AES, EncryUtils.EncryptMode.CTR);
        Log.e("test","AES ----- CTR:"+ AesEncryptCTR +  "   " + EncryUtils.AesDesDecrypt(AesEncryptCTR,AES_KEY,AES_IV,EncryUtils.Encryption.AES, EncryUtils.EncryptMode.CTR));

        String AesEncryptOFB = EncryUtils.AesDesEncrypt(strTestData,AES_KEY,AES_IV,EncryUtils.Encryption.AES, EncryUtils.EncryptMode.OFB);
        Log.e("test","AES ----- OFB:"+ AesEncryptOFB +  "   " + EncryUtils.AesDesDecrypt(AesEncryptOFB,AES_KEY,AES_IV, EncryUtils.Encryption.AES,EncryUtils.EncryptMode.OFB));

        /**
         * DES 加解密
         */
        String DesEncryptECB = EncryUtils.AesDesEncrypt(strTestData,DES_KEY,"",EncryUtils.Encryption.DES, EncryUtils.EncryptMode.ECB);
        Log.e("test","DES ----- ECB:"+ DesEncryptECB +  "   " + EncryUtils.AesDesDecrypt(DesEncryptECB,DES_KEY,"", EncryUtils.Encryption.DES,EncryUtils.EncryptMode.ECB));

        String DesEncryptCBC = EncryUtils.AesDesEncrypt(strTestData,DES_KEY,DES_IV,EncryUtils.Encryption.DES, EncryUtils.EncryptMode.CBC);
        Log.e("test","DES ----- CBC:"+ DesEncryptCBC +  "   " + EncryUtils.AesDesDecrypt(DesEncryptCBC,DES_KEY,DES_IV,EncryUtils.Encryption.DES, EncryUtils.EncryptMode.CBC));

        String DesEncryptCFB = EncryUtils.AesDesEncrypt(strTestData,DES_KEY,DES_IV,EncryUtils.Encryption.DES, EncryUtils.EncryptMode.CFB);
        Log.e("test","DES ----- CFB:"+ DesEncryptCFB +  "   " + EncryUtils.AesDesDecrypt(DesEncryptCFB,DES_KEY,DES_IV,EncryUtils.Encryption.DES, EncryUtils.EncryptMode.CFB));

        String DesEncryptCTR = EncryUtils.AesDesEncrypt(strTestData,DES_KEY,DES_IV,EncryUtils.Encryption.DES, EncryUtils.EncryptMode.CTR);
        Log.e("test","DES ----- CTR:"+ DesEncryptCTR +  "   " + EncryUtils.AesDesDecrypt(DesEncryptCTR,DES_KEY,DES_IV,EncryUtils.Encryption.DES, EncryUtils.EncryptMode.CTR));

        String DesEncryptOFB = EncryUtils.AesDesEncrypt(strTestData,DES_KEY,DES_IV,EncryUtils.Encryption.DES, EncryUtils.EncryptMode.OFB);
        Log.e("test","DES ----- OFB:"+ DesEncryptOFB +  "   " + EncryUtils.AesDesDecrypt(DesEncryptOFB,DES_KEY,DES_IV, EncryUtils.Encryption.DES,EncryUtils.EncryptMode.OFB));

        /**
         * DES3 加解密
         */
        String Des3EncryptECB = EncryUtils.AesDesEncrypt(strTestData,DES3_KEY,"",EncryUtils.Encryption.DES3, EncryUtils.EncryptMode.ECB);
        Log.e("test","DES3----- ECB:"+ Des3EncryptECB +  "   " + EncryUtils.AesDesDecrypt(Des3EncryptECB,DES3_KEY,"", EncryUtils.Encryption.DES3,EncryUtils.EncryptMode.ECB));

        String Des3EncryptCBC = EncryUtils.AesDesEncrypt(strTestData,DES3_KEY,DES3_IV,EncryUtils.Encryption.DES3, EncryUtils.EncryptMode.CBC);
        Log.e("test","DES3----- CBC:"+ Des3EncryptCBC +  "   " + EncryUtils.AesDesDecrypt(Des3EncryptCBC,DES3_KEY,DES3_IV,EncryUtils.Encryption.DES3, EncryUtils.EncryptMode.CBC));

        String Des3EncryptCFB = EncryUtils.AesDesEncrypt(strTestData,DES3_KEY,DES3_IV,EncryUtils.Encryption.DES3, EncryUtils.EncryptMode.CFB);
        Log.e("test","DES3----- CFB:"+ Des3EncryptCFB +  "   " + EncryUtils.AesDesDecrypt(Des3EncryptCFB,DES3_KEY,DES3_IV,EncryUtils.Encryption.DES3, EncryUtils.EncryptMode.CFB));

        String Des3EncryptCTR = EncryUtils.AesDesEncrypt(strTestData,DES3_KEY,DES3_IV,EncryUtils.Encryption.DES3, EncryUtils.EncryptMode.CTR);
        Log.e("test","DES3----- CTR:"+ Des3EncryptCTR +  "   " + EncryUtils.AesDesDecrypt(Des3EncryptCTR,DES3_KEY,DES3_IV,EncryUtils.Encryption.DES3, EncryUtils.EncryptMode.CTR));

        String Des3EncryptOFB = EncryUtils.AesDesEncrypt(strTestData,DES3_KEY,DES3_IV,EncryUtils.Encryption.DES3, EncryUtils.EncryptMode.OFB);
        Log.e("test","DES3----- OFB:"+ Des3EncryptOFB +  "   " + EncryUtils.AesDesDecrypt(Des3EncryptOFB,DES3_KEY,DES3_IV, EncryUtils.Encryption.DES3,EncryUtils.EncryptMode.OFB));

        RSAUtilTest();
        createRsaKey();
    }


    /**
     * RSA 加解密
     */
    private void RSAUtilTest(){
        try {
            //加密数据
            String rsaTestData = "asdgasgegesgasdgasgegesgasdgasgegesgasdgasgegesgasdgasgegesgasdgasgegesgasdegfsgeasdegfsgeasdgasgegesgasdegfsgeasdegfsgeasdegfsgeasdegfsgeasdgasgegesgasdegfsgeasdegfsge";
            //公钥加密 私钥解密
            String encryptPub = RSAUtil.EncryptDataOfPublicKey(rsaTestData,mContext.getResources().openRawResource(R.raw.rsa_public_key));
            String decryptPri = RSAUtil.DecryptDataOfPrivateKey(encryptPub,mContext.getResources().openRawResource(R.raw.rsa_private_key));
            Log.e("test","----1--- : " + String.format("%s\n\r%s",encryptPub,decryptPri));

            //私钥加密 公钥解密
            String encryptPri = RSAUtil.EncryptDataOfPrivateKey(rsaTestData,mContext.getResources().openRawResource(R.raw.rsa_private_key));
            String decryptPub = RSAUtil.DecryptDataOfPublicKey(encryptPri,mContext.getResources().openRawResource(R.raw.rsa_public_key));
            Log.e("test","----2--- : " + String.format("%s\n\r%s",encryptPri,decryptPub));

            /**
             * 密钥对  M E 形式的
             */
            String publicModulus = "c1209bfb8f649d891be8f0f32e79ed227800a0a845083cf6b51a217de84e03d442e180b57ad05b155d3f1996c8fb9cb9f233e14846c02cd2991c70216d626221220a6f136936a517c3f73328ad369a12d1d13fc5af6bb2dce04530ab016f101fc90898c6a1afd944e147d16995b90a471add8ee9f8737f57f6bf2d6f52a741ef";
            String publicExponent = "010001";
            String privateExponent = "c1209bfb8f649d891be8f0f32e79ed227800a0a845083cf6b51a217de84e03d442e180b57ad05b155d3f1996c8fb9cb9f233e14846c02cd2991c70216d626221220a6f136936a517c3f73328ad369a12d1d13fc5af6bb2dce04530ab016f101fc90898c6a1afd944e147d16995b90a471add8ee9f8737f57f6bf2d6f52a741ef";
            String privateModulus = "35f8b1fec45cfef5913a311414d9f81e58e0fc04ea7dd9e3ac4ae82f329b92d05ffc7b26bc72bbf1a5847bd73ac5ae4ffcd2e8d3750a41bc7d1388769f060e9bed2669b0e5c1f62cb9e33ea663506554997dd10276902aac4affca89c066dc6fac9720715e6f85c005ec4e18fa9d9acaeb7ecf11cf71fb0c45b1110ea66ec5b1";

            //公钥加密 私钥解密
            String encryptPubME = RSAUtil.EncryptDataOfPublicKey(rsaTestData,publicModulus,publicExponent);
            String decryptPriME = RSAUtil.DecryptDataOfPrivateKey(encryptPubME,privateExponent,privateModulus);
            Log.e("test","----1 ME--- : " + String.format("%s\n\r%s",encryptPubME,decryptPriME));

            //私钥加密 公钥解密
            String encryptPriME = RSAUtil.EncryptDataOfPrivateKey(rsaTestData,privateExponent,privateModulus);
            String decryptPubME = RSAUtil.DecryptDataOfPublicKey(encryptPriME,publicModulus,publicExponent);
            Log.e("test","----2 ME--- : " + String.format("%s\n\r%s",encryptPriME,decryptPubME));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 生成RSA key
     * 网上生成密钥对  http://web.chacuo.net/netrsakeypair
     */
    private void createRsaKey(){
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            //密钥位数
            keyPairGen.initialize(1024);
            //密钥对
            KeyPair keyPair = keyPairGen.generateKeyPair();
            // 公钥
            PublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            // 私钥
            PrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

            String publicKeyString = getKeyString(publicKey);
            Log.e("test","--------- public:\n" + publicKeyString);

            String privateKeyString = getKeyString(privateKey);
            Log.e("test","--------- private:\n" + privateKeyString);

            Log.e("test","------ Public Modulus  :" + ((RSAPublicKey)publicKey).getModulus().toString(16));
            Log.e("test","------ Public Exponent :" + ((RSAPublicKey)publicKey).getPublicExponent());

            Log.e("test","------ private Modulus  :" + ((RSAPrivateKey)privateKey).getModulus().toString(16));
            Log.e("test","------ private Exponent :" + ((RSAPrivateKey)privateKey).getPrivateExponent().toString(16));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    /**
     * 得到密钥字符串（经过base64编码）
     * @return
     */
    public static String getKeyString(Key key) throws Exception {
        byte[] keyBytes = key.getEncoded();
        String s = Base64.encodeToString(keyBytes,Base64.NO_WRAP);
        return s;
    }
}

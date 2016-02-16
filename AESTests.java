
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.spec.*;

import java.util.*;
import java.security.*;

public class AESTests {

    public static void main(String [ ] args)
    {
       System.loadLibrary("jnitests");

       Random random = new Random();
       byte[] iv  = new byte[16];
       random.nextBytes(iv);
       iv[14] = iv[15] = 0;
       byte[] key = new byte[16];
       random.nextBytes(key);
       byte[] buf = new byte[1000];
       random.nextBytes(buf);
       int offset = 20;
       //use an odd number here
       int testround = 1000001;

       byte[] openssl_buf = Arrays.copyOf(buf, buf.length);
       OPENSSL_CTR(iv, key, openssl_buf, offset, openssl_buf.length - offset, testround);

       byte[] java_buf = Arrays.copyOf(buf, buf.length);
       JAVA_CTR(iv, key, java_buf, offset, java_buf.length - offset, testround);

       byte[] jce_buf = Arrays.copyOf(buf, buf.length);
       JCE_CTR(iv, key, jce_buf, offset, jce_buf.length - offset, testround);

       byte[] bc_buf = Arrays.copyOf(buf, buf.length);
       BC_CTR(iv, key, bc_buf, offset, bc_buf.length - offset, testround);

       byte[] SunPKCS11_buf = Arrays.copyOf(buf, buf.length);
       SunPKCS11_CTR(iv, key, SunPKCS11_buf, offset, SunPKCS11_buf.length - offset, testround);

       System.out.println("equals : "+ Arrays.equals(openssl_buf, java_buf));
       System.out.println("equals : "+ Arrays.equals(openssl_buf, jce_buf));
       System.out.println("equals : "+ Arrays.equals(openssl_buf, bc_buf));
       System.out.println("equals : "+ Arrays.equals(openssl_buf, SunPKCS11_buf));
       System.out.println("equals : "+ Arrays.equals(openssl_buf, buf));
    }

    private static void JCE_CTR(byte[] iv, byte[] key, byte[] inOut, int offset, int len, int testround)
    {
       try {
           Cipher ciphertest = Cipher.getInstance("AES/CTR/NoPadding", "SunJCE");

           long time = System.nanoTime();
           for(int r=0; r<testround; r++) {
               SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
               AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
               ciphertest.init(Cipher.ENCRYPT_MODE, secretKeySpec, paramSpec);
               ciphertest.doFinal(inOut, offset, len, inOut, offset);
           }
           System.out.println("JCE_CTR : "+ ((System.nanoTime() - time)/testround));
       } catch (Exception e) {
           System.out.println("JCE_CTR : "+ e);
       }
    }

    private static void SunPKCS11_CTR(byte[] iv, byte[] key, byte[] inOut, int offset, int len, int testround)
    {
       try {
           Provider provider = new sun.security.pkcs11.SunPKCS11("--name=test456\\n"
                   + "nssDbMode=noDb\\n"
                   + "attributes=compatibility");
           Cipher ciphertest = Cipher.getInstance("AES/CTR/NoPadding", provider);

           long time = System.nanoTime();
           for(int r=0; r<testround; r++) {
               SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
               AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
               ciphertest.init(Cipher.ENCRYPT_MODE, secretKeySpec, paramSpec);
               ciphertest.doFinal(inOut, offset, len, inOut, offset);
           }
           System.out.println("SunPKCS11_CTR : "+ ((System.nanoTime() - time)/testround));
       } catch (Exception e) {
           System.out.println("SunPKCS11_CTR : "+ e);
       }
    }

    private static void BC_CTR(byte[] iv, byte[] key, byte[] inOut, int offset, int len, int testround)
    {
       try {
           Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
           Cipher ciphertest = Cipher.getInstance("AES/CTR/NoPadding", "BC");

           long time = System.nanoTime();
           for(int r=0; r<testround; r++) {
               SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
               AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
               ciphertest.init(Cipher.ENCRYPT_MODE, secretKeySpec, paramSpec);
               ciphertest.doFinal(inOut, offset, len, inOut, offset);
           }
           System.out.println("BC_CTR : "+ ((System.nanoTime() - time)/testround));
       } catch (Exception e) {
           System.out.println("BC_CTR : "+ e);
       }
    }

    public static final int BLKLEN = 16;

    public static void JAVA_CTR(byte[] iv, byte[] key, byte[] inOut, int offset, int len, int testround)
    {
        try {
        // "AES/ECB/NoPadding" is ~2 times faster than "AES" ...
        Cipher ciphertest = Cipher.getInstance("AES/ECB/NoPadding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        ciphertest.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        byte[] cipherStream = new byte[2048];

        long time = System.nanoTime();
        for(int r=0; r<testround; r++) {
            int lencipherstream;
            if ((len % BLKLEN) == 0)
                lencipherstream = len;
            else
                lencipherstream = len - (len % BLKLEN) + BLKLEN;

            for (int ctr = 0, ctrEnd = lencipherstream / BLKLEN; ctr < ctrEnd; ctr++)
            {
                // compute the cipher stream
                //iv[14] = (byte) ((ctr & 0xFF00) >> 8);
                //iv[15] = (byte) (ctr & 0x00FF);
                ciphertest.doFinal(iv, 0, BLKLEN, cipherStream, ctr * BLKLEN);
                if (++iv[15] == 0) ++iv[14];
            }
            //reset iv to start value
            iv[14] = iv[15] = 0;

            for (int i = 0; i < len; i++)
                inOut[i + offset] ^= cipherStream[i];
        }
        System.out.println("JAVA_CTR : "+ ((System.nanoTime() - time)/testround));

        } catch (Exception e) {
            System.out.println("JAVA_CTR : "+ e);
        }
    }

    private static native long OPENSSL_CTR_CTX_create();
    private static native void OPENSSL_CTR_CTX_destroy(long ctx);
    private static native boolean OPENSSL_CTR_CTX_compute(long ctx, byte[] iv, byte[] key, byte[] inOut, int offset, int len);
    
    public static void OPENSSL_CTR(byte[] iv, byte[] key, byte[] inOut, int offset, int len, int testround)
    {
        long ctx = OPENSSL_CTR_CTX_create();
        long time = System.nanoTime();
        for(int r=0; r<testround; r++) {
            OPENSSL_CTR_CTX_compute(ctx, iv, key, inOut, offset, len);
        }
        System.out.println("OPENSSL_CTR : "+ ((System.nanoTime() - time)/testround));
        OPENSSL_CTR_CTX_destroy(ctx);
    }

    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
}


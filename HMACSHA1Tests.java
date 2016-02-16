import java.security.Provider;
import java.security.Security;
import java.util.Random;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class HMACSHA1Tests {


    public static void main(String [ ] args)
    {
        System.loadLibrary("jnitests");

        Random random = new Random();
        byte[] key = new byte[16];
        random.nextBytes(key);
        byte[] roc = new byte[4];
        random.nextBytes(roc);
        byte[] buf = new byte[1020];
        random.nextBytes(buf);
        int offset = 20;
        int len = 1000;
        //use an odd number here
        int testround = 1000001;

        //for(Provider p: Security.getProviders())
        //    System.out.println(p.toString());

        OPENSSL2_HMACSHA1(key, buf, roc, offset, len - offset, testround);
        OPENSSL1_HMACSHA1(key, buf, roc, offset, len - offset, testround);
        SunPKCS11_HMACSHA1(key, buf, roc, offset, len - offset, testround);
        JCE_HMACSHA1(key, buf, roc, offset, len - offset, testround);
        BC_HMACSHA1(key, buf, roc, offset, len - offset, testround);
    }

    private static void JCE_HMACSHA1(byte[] key, byte[] inOut, byte[] roc, int offset, int len, int testround)
    {
        try {
            Mac mac = Mac.getInstance("HmacSHA1", "SunJCE");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));

            long time = System.nanoTime();
            for(int r=0; r<testround; r++) {
                mac.update(inOut, offset, len);
                mac.update(roc);
                mac.doFinal(inOut, offset + len);
            }
            System.out.println("JCE_HMACSHA1 : "+ ((System.nanoTime() - time)/testround));
        } catch (Exception e) {
            System.out.println("JCE_HMACSHA1 : "+ e);
        }
    }

    private static void SunPKCS11_HMACSHA1(byte[] key, byte[] inOut, byte[] roc, int offset, int len, int testround)
    {
        try {
            Provider provider = new sun.security.pkcs11.SunPKCS11("--name=test456\\n"
                                            + "nssDbMode=noDb\\n"
                                            + "attributes=compatibility");
            Mac mac = Mac.getInstance("HmacSHA1", provider);
            mac.init(new SecretKeySpec(key, "HmacSHA1"));

            long time = System.nanoTime();
            for(int r=0; r<testround; r++) {
                mac.update(inOut, offset, len);
                mac.update(roc);
                mac.doFinal(inOut, offset + len);
            }
            System.out.println("SunPKCS11_HMACSHA1 : "+ ((System.nanoTime() - time)/testround));
        } catch (Exception e) {
            System.out.println("SunPKCS11_HMACSHA1 : "+ e);
        }
    }

    private static void BC_HMACSHA1(byte[] key, byte[] inOut, byte[] roc, int offset, int len, int testround)
    {
        try {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            Mac mac = Mac.getInstance("HmacSHA1", "BC");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));

            long time = System.nanoTime();
            for(int r=0; r<testround; r++) {
                mac.update(inOut, offset, len);
                mac.update(roc);
                mac.doFinal(inOut, offset + len);
            }
            System.out.println("BC_HMACSHA1 : "+ ((System.nanoTime() - time)/testround));
        } catch (Exception e) {
            System.out.println("BC_HMACSHA1 : "+ e);
        }
    }

    private static native boolean OPENSSL_HMACSHA1_process(byte[] key, byte[] inOut, int inOffset, int inLen, int outOffset);

    private static void OPENSSL1_HMACSHA1(byte[] key, byte[] inOut, byte[] roc, int offset, int len, int testround)
    {
        try {
            long time = System.nanoTime();
            for(int r=0; r<testround; r++) {
                inOut[len + 0] = roc[0];
                inOut[len + 1] = roc[1];
                inOut[len + 2] = roc[2];
                inOut[len + 3] = roc[3];
                if (!OPENSSL_HMACSHA1_process(key, inOut, offset, len + 4, offset + len))
                    throw new Exception("aaa");
            }
            System.out.println("OPENSSL1_HMACSHA1 : "+ ((System.nanoTime() - time)/testround));
        } catch (Exception e) {
            System.out.println("OPENSSL1_HMACSHA1 : "+ e);
        }
    }

    private static native long OPENSSL_HMACSHA1_CTX_create();
    private static native void OPENSSL_HMACSHA1_CTX_destroy(long ctx);
    private static native boolean OPENSSL_HMACSHA1_CTX_init(long ctx, byte[] key);
    private static native boolean OPENSSL_HMACSHA1_CTX_process(long ctx, byte[] inOut, int inOffset, int inLen, int outOffset);

    private static void OPENSSL2_HMACSHA1(byte[] key, byte[] inOut, byte[] roc, int offset, int len, int testround)
    {
        try {
            long ctx = OPENSSL_HMACSHA1_CTX_create();
            if (!OPENSSL_HMACSHA1_CTX_init(ctx, key))
                throw new Exception("init");
            long time = System.nanoTime();
            for(int r=0; r<testround; r++) {
                inOut[len + 0] = roc[0];
                inOut[len + 1] = roc[1];
                inOut[len + 2] = roc[2];
                inOut[len + 3] = roc[3];
                if (!OPENSSL_HMACSHA1_CTX_process(ctx, inOut, offset, len + 4, offset + len))
                    throw new Exception("process");
            }
            System.out.println("OPENSSL2_HMACSHA1 : "+ ((System.nanoTime() - time)/testround));
        } catch (Exception e) {
            System.out.println("OPENSSL2_HMACSHA1 : "+ e);
        }
    }
}
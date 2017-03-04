package xiuuu;

import java.io.InputStream;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLConnection;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class DiffieHellman {

    private static final SecureRandom rnd = new SecureRandom();

    public static boolean miller_rabin_pass(BigInteger a, BigInteger n) {
        BigInteger n_minus_one = n.subtract(BigInteger.ONE);
        BigInteger d = n_minus_one;
        int s = d.getLowestSetBit();
        d = d.shiftRight(s);
        BigInteger a_to_power = a.modPow(d, n);
        if (a_to_power.equals(BigInteger.ONE)) {
            return true;
        }
        for (int i = 0; i < s - 1; i++) {
            if (a_to_power.equals(n_minus_one)) {
                return true;
            }
            a_to_power = a_to_power.multiply(a_to_power).mod(n);
        }
        if (a_to_power.equals(n_minus_one)) {
            return true;
        }
        return false;
    }

    public static boolean miller_rabin(BigInteger n) {
        for (int repeat = 0; repeat < 20; repeat++) {
            BigInteger a;
            do {
                a = new BigInteger(n.bitLength(), rnd);
            } while (a.equals(BigInteger.ZERO));
            if (!miller_rabin_pass(a, n)) {
                return false;
            }
        }
        return true;
    }

    public static boolean isPrime(BigInteger r) {
        return miller_rabin(r);
    }

    public static List<BigInteger> primeFactors(BigInteger number) {
        BigInteger n = number;
        BigInteger i = BigInteger.valueOf(2);
        BigInteger limit = BigInteger.valueOf(10000);
        List<BigInteger> factors = new ArrayList<BigInteger>();
        while (!n.equals(BigInteger.ONE)) {
            while (n.mod(i).equals(BigInteger.ZERO)) {
                factors.add(i);
                n = n.divide(i);

                if (isPrime(n)) {
                    factors.add(n);
                    return factors;
                }
            }
            i = i.add(BigInteger.ONE);
            if (i.equals(limit)) {
                return factors;
            }
        }
        System.out.println(factors);
        return factors;
    }

    public static boolean isPrimeRoot(BigInteger g, BigInteger p) {
        BigInteger totient = p.subtract(BigInteger.ONE); 
        List<BigInteger> factors = primeFactors(totient);
        int i = 0;
        int j = factors.size();
        for (; i < j; i++) {
            BigInteger factor = factors.get(i);
            BigInteger t = totient.divide(factor);
            if (g.modPow(t, p).equals(BigInteger.ONE)) {
                return false;
            }
        }
        return true;
    }


    public static BigInteger findPrimeRoot(BigInteger p) {
        int start = 2001;

        for (int i = start; i < 100000000; i++) {
            if (isPrimeRoot(BigInteger.valueOf(i), p)) {
                return BigInteger.valueOf(i);
            }
        }
        return BigInteger.valueOf(0);
    }
}

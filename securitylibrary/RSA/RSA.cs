using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            int i, n, cipherText = 1;

            n = p * q;

            for (i = 0; i < e; i++)
            {
                cipherText *= M;
                cipherText = cipherText % n;
            }

            cipherText %= n;
            return cipherText;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            int n, d, i;
            int mulInverse = 0, phi = 0, plainText = 1;

            n = p * q;
            phi = (p - 1) * (q - 1);

            i = 1;
            while (mulInverse != 1)
            {
                mulInverse = (e * i) % phi;
                i++;
            }

            mulInverse = i - 1;

            d = mulInverse % phi;

            for (i = 0; i < d; i++)
            {
                plainText *= C;
                plainText = plainText % n;
            }

            plainText %= n;
            return plainText;

        }
    }
}

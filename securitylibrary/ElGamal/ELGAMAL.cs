using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            int i, c1 = 1, c2 = 1, K = 1;
            List<long> cipherText = new List<long>();

            for (i = 0; i < k; i++)
            {
                c1 *= alpha;
                c1 %= q;
            }

            c1 %= q;

            for (i = 0; i < k; i++)
            {
                K *= y;
                K %= q;
            }

            K %= q;

            c2 = (m * K) % q;

            cipherText.Add((long)c1);
            cipherText.Add((long)c2);

            return cipherText;

        }
        public int Decrypt(int c1, int c2, int x, int q)
        {

            int i, K = 1, M = 0, mulInverse = 0;

            for (i = 0; i < x; i++)
            {
                K *= c1;
                K %= q;
            }

            K %= q;

            i = 1;
            while (mulInverse != 1)
            {
                mulInverse = (K * i) % q;
                i++;
            }

            mulInverse = i - 1;

            M = (c2 * mulInverse) % q;

            return M;

        }
    }
}

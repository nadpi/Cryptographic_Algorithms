using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            List<int> Key = new List<int>();
            int aPublicKey = alpha, bPublicKey = alpha, i = 0, key1 = 1, key2 = 1;
            
            for(i = 1; i < xa; i++)
            {
                aPublicKey *= alpha;
                aPublicKey = aPublicKey % q;
            }

            for (i = 1; i < xb; i++)
            {
                bPublicKey *= alpha;
                bPublicKey = bPublicKey % q;
            }

            for (i = 0; i < xb; i++)
            {
                key1 *= aPublicKey;
                key1 = key1 % q;
            }

            for (i = 0; i < xa; i++)
            {
                key2 *= bPublicKey;
                key2 = key2 % q;
            }

            Key.Add(key1);
            Key.Add(key2);
            return Key;
        }
    }
}

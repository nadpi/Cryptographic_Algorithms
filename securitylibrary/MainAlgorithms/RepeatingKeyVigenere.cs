using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {

        public string Analyse(string plainText, string cipherText)
        {
            string key = "";

            int ctlen = cipherText.Length;
            cipherText = cipherText.ToLower();
            for (int i = 0; i < ctlen; i++)
            {

                int c = (cipherText[i] - plainText[i]);
                if (c >= 0)
                    key += (char)('a' + (c));
                else
                    key += (char)('a' + (c + 26));
            }
            string k = string.Join("", key.Distinct()), newKey = "";
            int keylen = key.Length;
            for (int i = 0; i < keylen; i++)
            {
                if (i > k.Length && key[i] == k[0])
                {
                    break;
                }
                newKey += key[i];
            }
            return newKey;
        }

        public string Decrypt(string cipherText, string key)
        {
            string plainText = "";
            int ctlen = cipherText.Length;
            int keylen = key.Length;
            cipherText = cipherText.ToLower();

            for (int i = 0; i < ctlen; i++)
            {
                if (ctlen > keylen && i <= ctlen - keylen)
                {
                    key += key[i];
                }
                int c = (cipherText[i] - key[i]);
                if (c >= 0)
                    plainText += (char)('a' + (c));
                else
                    plainText += (char)('a' + (c + 26));
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            int ptlen = plainText.Length;
            int keylen = key.Length;

            string ct = "";

            for (int i = 0; i < ptlen; i++)
            {
                if (ptlen > keylen && i <= ptlen - keylen)
                {
                    key += key[i];
                }

                char c = (char)(key[i] + (plainText[i] - 'a'));

                while (c > 'z')
                {
                    c -= (char)26;
                }

                ct += c;
            }

            return ct;
        }
    }
}
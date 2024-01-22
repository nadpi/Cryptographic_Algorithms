using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {

        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            string key = "";
            int ctlen = cipherText.Length;
            for (int i = 0; i < ctlen; i++)
            {

                int c = (cipherText[i] - plainText[i]);
                if (c >= 0)
                    key += (char)('a' + (c));
                else
                    key += (char)('a' + (c + 26));
            }
            string newKey = "";
            for (int i = 0; i < ctlen; i++)
            {
                if (key[i] == plainText[0])
                {
                    int counter = 0;
                    int k = 0;
                    for (int j = i; j < ctlen; j++)
                    {
                        if (key[j] == plainText[k])
                        {
                            counter++;
                            k++;
                        }
                        else
                            break;
                    }
                    if (counter == ctlen - i)
                    { break; }
                }
                else
                {
                    newKey += key[i];
                }

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

                int c = (cipherText[i] - key[i]);

                if (c >= 0)
                    plainText += (char)('a' + (c));
                else
                    plainText += (char)('a' + (c + 26));

                if (ctlen > keylen && i <= ctlen - keylen)
                {
                    key += plainText[i];
                }
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
                    key += plainText[i];
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
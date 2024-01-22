using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        struct alphabet
        {
            public char charcter;
            public int number;
        }
        public string Encrypt(string plainText, int key)
        {
            alphabet[] alph = new alphabet[26];
            char[] cipher = new char[plainText.Length];
            string cipherall;
            int i, j, hold = 0, after = 0;
            char first = 'a';

            // Numerical representation for each character
            for (i = 0; i < 26; i++)
            {
                alph[i].charcter = first;
                alph[i].number = i;
                first++;
            }


            for (i = 0; i < plainText.Length; i++)
            {
                for (j = 0; j < 26; j++)
                {
                    if (plainText[i] == alph[j].charcter)
                    {
                        hold = alph[j].number;
                        break;
                    }
                }
                after = hold + key;
                cipher[i] = alph[after % 26].charcter;
            }
            cipherall = new string(cipher);
            return cipherall.ToUpper();
        }

        public string Decrypt(string cipherText, int key)
        {
            alphabet[] alph = new alphabet[26];
            char[] plain = new char[cipherText.Length];
            string plainall;
            int i, j, hold = 0, after = 0;
            char first = 'A';

            // Numerical representation for each character
            for (i = 0; i < 26; i++)
            {
                alph[i].charcter = first;
                alph[i].number = i;
                first++;
            }

            for (i = 0; i < cipherText.Length; i++)
            {
                for (j = 0; j < 26; j++)
                {
                    if (cipherText[i] == alph[j].charcter)
                    {
                        hold = alph[j].number;
                        break;
                    }
                }
                after = hold - key;
                if (after < 0)
                    plain[i] = alph[26 - (after * -1) % 26].charcter;
                else
                    plain[i] = alph[after % 26].charcter;
            }
            plainall = new string(plain);
            return plainall.ToLower();
        }

        public int Analyse(string plainText, string cipherText)
        {
            Ceaser algo = new Ceaser();
            int i = 0, key = 0;
            string cipher;
            for (i = 0; i < 26; i++)
            {
                cipher = algo.Encrypt(plainText, i);
                if (cipher.Equals(cipherText))
                {
                    key = i;
                    break;
                }
            }
            return key;
        }
    }
}

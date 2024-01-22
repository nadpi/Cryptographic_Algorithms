using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        struct alphabet
        {
            public char charcter;
            public char equ;
        }
        public string Analyse(string plainText, string cipherText)
        {
            alphabet[] alph = new alphabet[26];
            char first = 'a';
            char[] arr;
            char[] key = new char[26];
            int i, j, h = 0, cnt = 0, l = 0, flag = 0;
            string keystr;
            cipherText = cipherText.ToLower();

            // Store the alphabet
            for (i = 0; i < 26; i++)
            {
                alph[i].charcter = first;
                first++;
            }


            for (i = 0; i < 26; i++)
            {
                alph[i].equ = ' ';
            }


            for (i = 0; i < 26; i++)
            {
                for (j = 0; j < plainText.Length; j++)
                {
                    if (plainText[j] == alph[i].charcter)
                    {
                        alph[i].equ = cipherText[j];
                        cnt++;
                    }
                }
            }
            arr = new char[26];

            // Store the rest of chars
            for (i = 0; i < 26; i++)
            {
                flag = 0;
                for (j = 0; j < 26; j++)
                {
                    if (alph[i].charcter == alph[j].equ)
                        flag = 1;
                }
                if (flag == 0)
                {
                    arr[h] = alph[i].charcter;
                    h++;
                }    
            }

            for (i = 0; i < 26; i++)
            {
                if (alph[i].equ != ' ')
                    key[i] = alph[i].equ;
                else
                {
                    key[i] = arr[l];
                    l++;
                }
            }
            keystr = new string(key);
            return keystr;
        }

        public string Decrypt(string cipherText, string key)
        {

            int i = 0, j = 0;
            alphabet[] arr = new alphabet[26];
            char[] plain = new char[cipherText.Length];
            char first = 'a';
            string plainall, cipherlow = cipherText.ToLower();

            // key representation/mapping for each character
            for (i = 0; i < key.Length; i++)
            {
                arr[i].charcter = first;
                arr[i].equ = key[i];
                first++;
            }

            // Mapping cipherText char to its equivalent key representation
            for (i = 0; i < cipherlow.Length; i++)
            {
                for (j = 0; j < key.Length; j++)
                {
                    if (cipherlow[i] == arr[j].equ)
                    {
                        plain[i] = arr[j].charcter;
                        break;
                    }
                }
            }
            plainall = new string(plain);
            return plainall;
        }

        public string Encrypt(string plainText, string key)
        {
            int i = 0, j = 0;
            alphabet[] arr = new alphabet[26];
            char[] cipher = new char[plainText.Length];
            char first = 'a';
            string cipherall;

            // key representation/mapping for each character
            for (i = 0; i < key.Length; i++)
            {
                arr[i].charcter = first;
                arr[i].equ = key[i];
                first++;
            }

            // Mapping plainText char to its equivalent key representation
            for (i = 0; i < plainText.Length; i++)
            {
                for (j = 0; j < key.Length; j++)
                {
                    if (plainText[i] == arr[j].charcter)
                    {
                        cipher[i] = arr[j].equ;
                        break;
                    }
                }
            }
            cipherall = new string(cipher);
            return cipherall.ToUpper();
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            alphabet[] alph = new alphabet[26];
            int i, cnt = 0, j = 0, h, max, idx = 0, m;
            int[] arr = new int[26];
            char first = 'a';
            cipher = cipher.ToLower();
            char[] storeplain = new char[cipher.Length];
            char[] chararr = { 'e', 't', 'a', 'o', 'i', 'n', 's', 'r', 'h', 'l', 'd', 'c', 'u', 'm', 'f', 'p', 'g', 'w', 'y', 'b', 'v', 'k', 'x', 'j', 'q', 'z' };

            // Store the alphabet
            for (i = 0; i < 26; i++)
            {
                alph[i].charcter = first;
                first++;
            }

            // Get the frequency of each character in the cipherText (arr[26])
            for (i = 0; i < 26; i++)
            {
                cnt = 0;
                cnt = cipher.Count(c => c == alph[i].charcter);
                arr[j] = cnt;
                j++;
            }


            for (i = 0; i < 26; i++)
            {
                // Get the max freq
                max = arr[0];
                for (h = 1; h < 26; h++)
                {
                    if (arr[h] > max)
                    {
                        max = arr[h];
                        idx = h;
                    }
                }
                // Replace the cipherText char with the equivalent frequency char (chararr[])
                for (m = 0; m < cipher.Length; m++)
                {
                    if (cipher[m] == alph[idx].charcter)
                    {
                        storeplain[m] = chararr[i];
                    }
                }
                arr[idx] = 0;
            }
            string plain = new string(storeplain);
            return plain;
        }
    }
}

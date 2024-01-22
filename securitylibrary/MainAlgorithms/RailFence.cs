using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            RailFence algo = new RailFence();
            int key = 1, i = 0;
            string plain;
            
            for (key = 1; key < plainText.Length; key++)
            {
                plain = algo.Encrypt(plainText, key);
                plain = plain.ToUpper();
                if (plain.Equals(cipherText))
                {
                    i = key;
                    break;
                }
            }
            return i;                
        }

        public string Decrypt(string cipherText, int key)
        {
            int columns = cipherText.Length / key, i, j, idx = 0;
            char[,] plain;
            char[] plainArr = new char[cipherText.Length];
            string plainStr;

            if (cipherText.Length % key != 0)
            {
                columns++;
            }

            plain = new char[key, columns];

            for (i = 0; i < key; i++)
            {
                for (j = 0; j < columns; j++)
                {
                    if (idx < cipherText.Length)
                    {
                        plain[i, j] = cipherText[idx];
                        idx++;
                    }
                    else
                        break;
                }
            }

            idx = 0;
            for (i = 0; i < columns; i++)
            {
                for (j = 0; j < key; j++)
                {
                    if (idx < cipherText.Length)
                    {
                        if (plain[j, i] == '\0')
                            break;
                        plainArr[idx] = plain[j, i];
                        idx++;
                    }
                    else
                        break;
                }
            }
            plainStr = new string(plainArr);
            return (plainStr);

        }

        public string Encrypt(string plainText, int key)
        {
            int columns = plainText.Length / key, i, j, idx = 0;
            char[ , ] cipher;
            char[] cipherArr = new char[plainText.Length];
            string cipherStr;

            if (plainText.Length % key != 0)
            {
                columns++;
            }

            cipher = new char[key, columns];

            for (i = 0; i < columns; i++)
            {
                for (j = 0; j < key; j++)
                {
                    if (idx < plainText.Length)
                    {
                        cipher[j, i] = plainText[idx];
                        idx++;
                    }
                    else
                        break;
                }
            }
            idx = 0;
            for(i = 0; i < key; i++)
            {
                for(j = 0; j < columns; j++)
                {
                    if (idx < plainText.Length)
                    {
                        if (cipher[i, j] == '\0')
                            break;
                        cipherArr[idx] = cipher[i, j];
                        idx++;
                    }
                    else
                        break;
                }
            }
            cipherStr = new string(cipherArr);

            Console.WriteLine(cipherStr);

            return (cipherStr);
        }
    }
}

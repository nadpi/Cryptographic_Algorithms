using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {



        public List<int> Analyse(string plainText, string cipherText)
        {
            string cipher;

            cipherText = cipherText.ToLower();
            for (int i = 2; true; i++)
            {
                int[] key = Enumerable.Range(1, i).ToArray<int>();

                while (key != null)
                {
                    cipher = Encrypt(plainText, key.ToList());
                    if (cipher == cipherText)
                    {
                        return key.ToList();
                    }
                    int order = key.Length;
                    if (key[0] == order && key[order - 1] == 1)
                    {
                        key = null;
                    }
                    else
                    {
                        int left = order - 2;
                        while ((key[left] > key[left + 1]) && (left >= 1))
                        {
                            left--;
                        }

                        int right = order - 1;
                        while (key[left] > key[right])
                        {
                            right--;
                        }

                        int tmp = key[left];
                        key[left] = key[right];
                        key[right] = tmp;

                        int x = left + 1;
                        int y = order - 1;
                        while (x < y)
                        {
                            tmp = key[x];
                            key[x++] = key[y];
                            key[y--] = tmp;
                        }
                    }
                }
            }
        }


        public string Decrypt(string cipherText, List<int> key)
        {

            string pt = "";
            int keylen = key.Count;
            int ctlen = cipherText.Length;
            int x = ctlen / keylen;
            char[,] mtrx = new char[keylen, x];
            char[,] ptMtrx = new char[x, keylen];
            int k = 0;

            for (int i = 0; i < keylen; i++)
            {
                for (int j = 0; j < x; j++)
                {
                    mtrx[i, j] = cipherText[k];
                    k++;
                }
            }

            for (int i = 0; i < keylen; i++)
            {
                for (int j = 0; j < x; j++)
                {
                    ptMtrx[j, key.IndexOf(i + 1)] = mtrx[i, j];
                }
            }
            for (int i = 0; i < x; i++)
            {
                for (int j = 0; j < keylen; j++)
                {
                    pt += ptMtrx[i, j];
                }
            }
            return pt;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            string ct = "";
            int ptlen = plainText.Length;
            int keylen = key.Count;
            int x = (ptlen / keylen) + 1;
            char[,] matriz = new char[x, keylen];
            int k = 0;
            int nOfrows = 0;

            for (int i = 0; i < x; i++)
            {
                for (int j = 0; j < keylen; j++)
                {

                    if (k < ptlen)
                    {

                        matriz[i, j] = plainText[k];
                        k++;
                    }
                }
                nOfrows++;
            }

            for (int i = 0; i < keylen; i++)
            {
                for (int j = 0; j < nOfrows; j++)
                {
                    if (matriz[j, key.IndexOf(i + 1)] != '\0')
                        ct += matriz[j, key.IndexOf(i + 1)];
                }
            }
            return ct;
        }
    }
}
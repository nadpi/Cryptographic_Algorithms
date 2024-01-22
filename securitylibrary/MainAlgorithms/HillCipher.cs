using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            int x, i, j, m, n, cnt = 0;
            List<int> key, resultantCipher;

            // which set is the one used for key
            for (i = 0; i < 26; i++)
            {
                for (j = 0; j < 26; j++)
                {
                    for (n = 0; n < 26; n++)
                    {
                        for (m = 0; m < 26; m++)
                        {
                            key = new List<int>(new[] { i, j, n, m });

                            resultantCipher = new List<int>(Encrypt(plainText, key));

                            for (x = 0; x < cipherText.Count(); x++)
                            {
                                if (cipherText[x] == resultantCipher[x])
                                    cnt++;
                            }

                            if (cnt == cipherText.Count())
                            {
                                return (key);
                            }
                            cnt = 0;
                        }
                    }
                }
            }
            // throw InvalidAnlysisException, when no key found
            throw new InvalidAnlysisException();
        }


        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            int det = 0, n = 0, x = 0, i, j;
            int idx = 0, mulInverse = 0;
            int[,] keyMatrix = new int[3, 3];
            int[,] newKeyMatrix = new int[3, 3];
            List<int> modifiedKey = new List<int>() { };
            List<int> adjMatrix = new List<int>() { };
            List<int> plain = new List<int>() { };

            if (key.Count() == 4)
            {
                // Rearrange keyMatrix
                modifiedKey.Add(key[0]);
                modifiedKey.Add(key[2]);
                modifiedKey.Add(key[1]);
                modifiedKey.Add(key[3]);

                // Calculate determinant for 2x2 keyMatrix
                det = (modifiedKey[0] * modifiedKey[3]) - (modifiedKey[1] * modifiedKey[2]);

                if (det == 0 || det % 13 == 0 || det % 2 == 0)
                    throw new System.Exception();

                if (det < 0)
                    det = 26 - (det * -1) % 26;

                // Get multiplicative inverse
                while (true)
                {
                    x++;
                    n = 0;
                    n = det * x;
                    n %= 26;
                    if (n == 1)
                        break;
                }

                // Adjoint Matrix
                adjMatrix.Add(modifiedKey[3]);
                adjMatrix.Add(modifiedKey[2] * -1);
                adjMatrix.Add(modifiedKey[1] * -1);
                adjMatrix.Add(modifiedKey[0]);

                // Multiply adjoint matrix by determinant   
                for (i = 0; i < adjMatrix.Count(); i++)
                {
                    adjMatrix[i] *= x;
                }

                // Matrix multiplication
                for (i = 0; i < cipherText.Count(); i += 2)
                {
                    plain.Add((adjMatrix[0] * cipherText[i]) + (adjMatrix[1] * cipherText[i + 1]));

                    plain.Add((adjMatrix[2] * cipherText[i]) + (adjMatrix[3] * cipherText[i + 1]));
                }

                
                for (i = 0; i < plain.Count(); i++)
                {
                    // When values < 0
                    if (plain[i] < 0)
                    {
                        plain[i] = (26 - ((plain[i] * -1) % 26)) % 26;
                    }
                    // When values > 25
                    else if (plain[i] > 25)
                    {
                        plain[i] = plain[i] % 26;

                    }
                }

            }
            else if (key.Count() == 9)
            {
                // Converting a list into a  2D array
                for (i = 0; i < 3; i++)
                {
                    for (j = 0; j < 3; j++)
                    {
                        keyMatrix[i, j] = key[idx];
                        idx++;
                    }
                }

                // Calculate determinant for 3x3 keyMatrix
                det += keyMatrix[0, 0] * ((keyMatrix[1, 1] * keyMatrix[2, 2]) - (keyMatrix[2, 1] * keyMatrix[1, 2]));
                det -= keyMatrix[0, 1] * ((keyMatrix[1, 0] * keyMatrix[2, 2]) - (keyMatrix[2, 0] * keyMatrix[1, 2]));
                det += keyMatrix[0, 2] * ((keyMatrix[2, 1] * keyMatrix[1, 0]) - (keyMatrix[1, 1] * keyMatrix[2, 0]));

                if (det < 0)
                    det = 26 - (det * -1) % 26;
                else
                    det = det % 26;

                // Get Multiplicative inverse
                i = 1;
                while (mulInverse != 1)
                {
                    mulInverse = (det * i) % 26;
                    i++;
                }

                mulInverse = i - 1;

                // Adjoint Matrix
                newKeyMatrix[0, 0] = mulInverse * ((keyMatrix[1, 1] * keyMatrix[2, 2]) - (keyMatrix[2, 1] * keyMatrix[1, 2]));
                newKeyMatrix[0, 1] = mulInverse * ((keyMatrix[1, 0] * keyMatrix[2, 2]) - (keyMatrix[2, 0] * keyMatrix[1, 2])) * -1;
                newKeyMatrix[0, 2] = mulInverse * ((keyMatrix[2, 1] * keyMatrix[1, 0]) - (keyMatrix[1, 1] * keyMatrix[2, 0]));

                newKeyMatrix[1, 0] = mulInverse * ((keyMatrix[0, 1] * keyMatrix[2, 2]) - (keyMatrix[2, 1] * keyMatrix[0, 2])) * -1;
                newKeyMatrix[1, 1] = mulInverse * ((keyMatrix[0, 0] * keyMatrix[2, 2]) - (keyMatrix[2, 0] * keyMatrix[0, 2]));
                newKeyMatrix[1, 2] = mulInverse * ((keyMatrix[0, 0] * keyMatrix[2, 1]) - (keyMatrix[2, 0] * keyMatrix[0, 1])) * -1;

                newKeyMatrix[2, 0] = mulInverse * ((keyMatrix[0, 1] * keyMatrix[1, 2]) - (keyMatrix[1, 1] * keyMatrix[0, 2]));
                newKeyMatrix[2, 1] = mulInverse * ((keyMatrix[0, 0] * keyMatrix[1, 2]) - (keyMatrix[1, 0] * keyMatrix[0, 2])) * -1;
                newKeyMatrix[2, 2] = mulInverse * ((keyMatrix[0, 0] * keyMatrix[1, 1]) - (keyMatrix[1, 0] * keyMatrix[0, 1]));

                // Prepare the keyMatrix
                for (i = 0; i < 3; i++)
                {
                    for (j = 0; j < 3; j++)
                    {
                        if (newKeyMatrix[i, j] < 0)
                            newKeyMatrix[i, j] = 26 - (newKeyMatrix[i, j] * -1) % 26;
                        else
                            newKeyMatrix[i, j] %= 26;
                    }
                }

                // Key matrix transpose
                for (i = 0; i < 3; i++)
                {
                    for (j = 0; j < 3; j++)
                    {
                        keyMatrix[i, j] = newKeyMatrix[j, i];
                    }
                }

                // Matrix Multiplication
                for (i = 0; i < cipherText.Count(); i += 3)
                {
                    plain.Add((keyMatrix[0, 0] * cipherText[i]) + (keyMatrix[0, 1] * cipherText[i + 1]) + (keyMatrix[0, 2] * cipherText[i + 2]));

                    plain.Add((keyMatrix[1, 0] * cipherText[i]) + (keyMatrix[1, 1] * cipherText[i + 1]) + (keyMatrix[1, 2] * cipherText[i + 2]));

                    plain.Add((keyMatrix[2, 0] * cipherText[i]) + (keyMatrix[2, 1] * cipherText[i + 1]) + (keyMatrix[2, 2] * cipherText[i + 2]));
                }



                for (i = 0; i < plain.Count(); i++)
                {
                    plain[i] = plain[i] % 26;

                }
            }

            return (plain);
        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int i, j = 0;

            List<int> result = new List<int>() { };

            if (key.Count() == 4)
            {
                // When plainText is odd
                if (plainText.Count() % 2 != 0)
                    plainText.Add(0);

                // Matrix Multiplication
                for (i = 0; i < plainText.Count(); i += 2)
                {
                    result.Add((key[0] * plainText[i]) + (key[1] * plainText[i + 1]));
                    result.Add((key[2] * plainText[i]) + (key[3] * plainText[i + 1]));
                }


                for (i = 0; i < result.Count(); i++)
                {
                    if (result[i] < 0)
                    {
                        result[i] = 26 - (result[i] * -1) % 26;
                    }
                    else if (result[i] > 25)
                    {
                        result[i] = result[i] % 26;
                    }
                }


            }
            else if (key.Count() == 9)
            {
                // Matrix Multiplication
                for (i = 0; i < plainText.Count(); i++)
                {
                    for (i = 0; i < plainText.Count(); i += 3)
                    {
                        result.Add((key[0] * plainText[i]) + (key[1] * plainText[i + 1]) + (key[2] * plainText[i + 2]));
                        result.Add((key[3] * plainText[i]) + (key[4] * plainText[i + 1]) + (key[5] * plainText[i + 2]));
                        result.Add((key[6] * plainText[i]) + (key[7] * plainText[i + 1]) + (key[8] * plainText[i + 2]));
                    }


                    for (i = 0; i < result.Count(); i++)
                    {
                        if (result[i] < 0)
                        {
                            result[i] = 26 - (result[i] * -1) % 26;
                        }
                        else if (result[i] > 25)
                        {
                            result[i] = result[i] % 26;
                        }
                    }
                }
            }

            return (result);
        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            int det = 0, i, j;
            int idx = 0, mulInverse = 0, id = 0;

            int[,] plainMatrix = new int[3, 3];
            int[,] cipherMatrix = new int[3, 3];
            int[,] newPlainMatrix = new int[3, 3];

            int[,] keyMatrix = new int[3, 3];
            int[,] transkeyMatrix = new int[3, 3];
            List<int> key = new List<int>() { };



            // Converting a list into a  2D array
            for (i = 0; i < 3; i++)
            {
                for (j = 0; j < 3; j++)
                {
                    plainMatrix[i, j] = plainText[idx];
                    idx++;
                }
            }

            det += plainMatrix[0, 0] * ((plainMatrix[1, 1] * plainMatrix[2, 2]) - (plainMatrix[2, 1] * plainMatrix[1, 2]));
            det -= plainMatrix[0, 1] * ((plainMatrix[1, 0] * plainMatrix[2, 2]) - (plainMatrix[2, 0] * plainMatrix[1, 2]));
            det += plainMatrix[0, 2] * ((plainMatrix[2, 1] * plainMatrix[1, 0]) - (plainMatrix[1, 1] * plainMatrix[2, 0]));

            if (det < 0)
                det = 26 - (det * -1) % 26;
            else
                det = det % 26;

            i = 1;
            while (mulInverse != 1)
            {
                mulInverse = (det * i) % 26;
                i++;
            }

            mulInverse = i - 1;

            // Plain matrix inverse for the rule (k = C x P-1) 
            newPlainMatrix[0, 0] = mulInverse * ((plainMatrix[1, 1] * plainMatrix[2, 2]) - (plainMatrix[2, 1] * plainMatrix[1, 2]));
            newPlainMatrix[0, 1] = mulInverse * ((plainMatrix[1, 0] * plainMatrix[2, 2]) - (plainMatrix[2, 0] * plainMatrix[1, 2])) * -1;
            newPlainMatrix[0, 2] = mulInverse * ((plainMatrix[2, 1] * plainMatrix[1, 0]) - (plainMatrix[1, 1] * plainMatrix[2, 0]));

            newPlainMatrix[1, 0] = mulInverse * ((plainMatrix[0, 1] * plainMatrix[2, 2]) - (plainMatrix[2, 1] * plainMatrix[0, 2])) * -1;
            newPlainMatrix[1, 1] = mulInverse * ((plainMatrix[0, 0] * plainMatrix[2, 2]) - (plainMatrix[2, 0] * plainMatrix[0, 2]));
            newPlainMatrix[1, 2] = mulInverse * ((plainMatrix[0, 0] * plainMatrix[2, 1]) - (plainMatrix[2, 0] * plainMatrix[0, 1])) * -1;

            newPlainMatrix[2, 0] = mulInverse * ((plainMatrix[0, 1] * plainMatrix[1, 2]) - (plainMatrix[1, 1] * plainMatrix[0, 2]));
            newPlainMatrix[2, 1] = mulInverse * ((plainMatrix[0, 0] * plainMatrix[1, 2]) - (plainMatrix[1, 0] * plainMatrix[0, 2])) * -1;
            newPlainMatrix[2, 2] = mulInverse * ((plainMatrix[0, 0] * plainMatrix[1, 1]) - (plainMatrix[1, 0] * plainMatrix[0, 1]));

            for (i = 0; i < 3; i++)
            {
                for (j = 0; j < 3; j++)
                {
                    if (newPlainMatrix[i, j] < 0)
                        newPlainMatrix[i, j] = 26 - (newPlainMatrix[i, j] * -1) % 26;
                    else
                        newPlainMatrix[i, j] %= 26;
                }
            }


            // Getting the transpose of the inverse matrix
            for (i = 0; i < 3; i++)
            {
                for (j = 0; j < 3; j++)
                {
                    plainMatrix[i, j] = newPlainMatrix[j, i];
                }
            }


            // Converting a 2D array into a  list
            idx = 0;
            for (i = 0; i < 3; i++)
            {
                for (j = 0; j < 3; j++)
                {
                    cipherMatrix[i, j] = cipherText[idx];
                    idx++;
                }
            }

            // Matrix multiplication
            for (i = 0; i < 3; i++)
            {
                for (j = 0; j < 3; j++)
                {
                    key.Add((plainMatrix[i, id] * cipherMatrix[id, id + j]) + (plainMatrix[i, id + 1] * cipherMatrix[id + 1, id + j]) + (plainMatrix[i, id + 2] * cipherMatrix[id + 2, id + j]));

                    id = 0;
                }
            }

            // Converting a list into a  2D array
            idx = 0;
            for (i = 0; i < 3; i++)
            {
                for (j = 0; j < 3; j++)
                {
                    keyMatrix[i, j] = key[idx];
                    idx++;
                }
            }

            // Getting the transpose of the key matrix
            for (i = 0; i < 3; i++)
            {
                for (j = 0; j < 3; j++)
                {
                    transkeyMatrix[i, j] = keyMatrix[j, i];
                }
            }

            idx = 0;
            for (i = 0; i < 3; i++)
            {
                for (j = 0; j < 3; j++)
                {
                    key[idx] = transkeyMatrix[i, j];
                    idx++;
                }
            }

            for (i = 0; i < key.Count(); i++)
            {
                key[i] = key[i] % 26;
            }

            return (key);
        }

    }
}

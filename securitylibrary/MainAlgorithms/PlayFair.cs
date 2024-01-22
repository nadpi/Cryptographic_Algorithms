using System;
using System.Linq;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public string Decrypt(string cipherText, string key)
        {
            char alpha = 'a';
            int index = 0, idx = 0, j = 0, i = 0, cnt = 0;
            int rows = 5, cols = 5;
            char[] restOfChars = new char[26];
            char[,] keyMatrix = new char[rows, cols];
            string[] charSets = new string[cipherText.Length];

            cipherText = cipherText.ToLower();

            // Handling the i/j case
            key = key.Replace('j', 'i');

            // Storing the rest of characters
            while (alpha <= 'z')
            {
                if (!(key.Contains(alpha)))
                {
                    if (alpha != 'j')
                    {
                        restOfChars[idx] = alpha;
                        idx++;
                    }
                }
                alpha++;
            }
            idx = 0;

            // Key matrix preparation
            for (i = 0; i < rows; i++)
            {
                for (j = 0; j < cols; j++)
                {
                    if (i == 0 && j == 0)
                    {
                        keyMatrix[0, 0] = key[index];
                        index++;
                        continue;
                    }
                    if (index < key.Length)
                    {
                        if (keyMatrix.Cast<char>().Contains(key[index]))
                        {
                            index++;
                            j--;
                            continue;
                        }
                        else
                        {
                            keyMatrix[i, j] = key[index];
                            index++;
                        }
                    }
                    else
                    {
                        keyMatrix[i, j] = restOfChars[idx];
                        idx++;
                    }
                }
            }

            // Message preparation
            cipherText = cipherText.ToLower();
            idx = 0;
            j = 0;

            while (cipherText[j] != '\0')
            {
                if (j == cipherText.Length - 1)
                {
                    charSets[idx] = cipherText[j].ToString() + 'x';
                    cnt++;
                    idx++;
                    break;
                }

                if (cipherText[j] == cipherText[j + 1])
                {
                    charSets[idx] = cipherText[j].ToString() + 'x';
                    cnt++;
                    idx++;
                }
                else
                {
                    charSets[idx] = cipherText[j].ToString() + cipherText[j + 1].ToString();
                    cnt++;
                    idx++;
                    j++;
                }
                j++;
                if (j > cipherText.Length - 1)
                    break;
            }
            charSets[idx] = "\0";

            // Encryption rules
            string plainText = "";
            char letter1, letter2, prevletter1 = ' ', prevletter2 = ' ';
            int row1, row2, col1, col2;

            for (int k = 0; charSets[k] != "\0"; k++)
            {
                letter1 = charSets[k][0];
                letter2 = charSets[k][1];
                row1 = 0;
                col1 = 0;
                row2 = 0;
                col2 = 0;


                // Find the positions (row and column)
                for (int r = 0; r < rows; r++)
                {
                    for (int c = 0; c < cols; c++)
                    {
                        if (keyMatrix[r, c] == letter1)
                        {
                            row1 = r;
                            col1 = c;
                        }
                        else if (keyMatrix[r, c] == letter2)
                        {
                            row2 = r;
                            col2 = c;
                        }
                    }
                }


                if (row1 == row2)
                {
                    // Increment the column position by 1 and wrap around to 0 if it reaches the last column
                    col1 = (col1 - 1) % 5;
                    col2 = (col2 - 1) % 5;

                    if (col1 < 0)
                        col1 = 5 + col1;
                    else if (col2 < 0)
                        col2 = 5 + col2;
                }
                else if (col1 == col2)
                {
                    // Increment the row position by 1 and wrap around to 0 if it reaches the last row
                    row1 = (row1 - 1) % 5;
                    row2 = (row2 - 1) % 5;

                    if (row1 < 0)
                        row1 = 5 + row1;
                    else if (row2 < 0)
                        row2 = 5 + row2;
                }
                else
                {
                    // Different row and different column, swap columns and keep rows
                    int tmp = col1;
                    col1 = col2;
                    col2 = tmp;
                }

                // Handling the 'x' character issue (when x is an actual letter in plainText)
                if (prevletter2 == 'x' && prevletter1 != keyMatrix[row1, col1] && k != cnt)
                {
                    plainText += prevletter2;
                }
                prevletter1 = keyMatrix[row1, col1];
                prevletter2 = keyMatrix[row2, col2];

                // Handling additional 'x' character issue (Duplicate letters)
                if (keyMatrix[row2, col2].ToString().ToLower() == "x")
                {
                    plainText += keyMatrix[row1, col1].ToString().ToLower();
                }
                else
                {
                    plainText += keyMatrix[row1, col1].ToString().ToLower() + keyMatrix[row2, col2].ToString().ToLower();
                }
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {

            char alpha = 'a';
            int index = 0, idx = 0, j = 0, i = 0;
            int rows = 5, cols = 5;
            char[] restOfChars = new char[26];
            char[,] keyMatrix = new char[rows, cols];
            string[] charSets = new string[plainText.Length];

            // Handling i/j case
            key = key.Replace('j', 'i');

            // Storing the rest of characters
            while (alpha <= 'z')
            {
                if (!(key.Contains(alpha)))
                {
                    if (alpha != 'j')
                    {
                        restOfChars[idx] = alpha;
                        idx++;
                    }
                }
                alpha++;
            }
            idx = 0;

            // Key matrix preparation
            for (i = 0; i < rows; i++)
            {
                for (j = 0; j < cols; j++)
                {
                    
                    if (i == 0 && j == 0)
                    {
                        keyMatrix[0, 0] = key[index];
                        index++;
                        continue;
                    }
                    if (index < key.Length)
                    {
                        // Check if letter was in keyMatrix already
                        if (keyMatrix.Cast<char>().Contains(key[index]))
                        {
                            index++;
                            j--;
                            continue;
                        }
                        else
                        {
                            keyMatrix[i, j] = key[index];
                            index++;
                        }
                    }
                    else
                    {
                        keyMatrix[i, j] = restOfChars[idx];
                        idx++;
                    }
                }
            }

            // Message preparation
            plainText = plainText.ToLower();
            idx = 0;
            j = 0;

            while (plainText[j] != '\0')
            {
                // x padding at the end of plainText
                if (j == plainText.Length - 1)
                {
                    charSets[idx] = plainText[j].ToString() + 'x';
                    idx++;
                    break;
                }
                // Duplicate letters case
                if (plainText[j] == plainText[j + 1])
                {
                    charSets[idx] = plainText[j].ToString() + 'x';
                    idx++;
                }
                else
                {
                    charSets[idx] = plainText[j].ToString() + plainText[j + 1].ToString();
                    idx++;
                    j++;
                }
                j++;
                if (j > plainText.Length - 1)
                    break;
            }
            charSets[idx] = "\0";

            // Encryption rules
            string cipherText = "";
            char letter1, letter2;
            int row1, row2, col1, col2;

            for (int k = 0; charSets[k] != "\0"; k++)
            {
                letter1 = charSets[k][0];
                letter2 = charSets[k][1];
                row1 = 0;
                col1 = 0;
                row2 = 0;
                col2 = 0;


                // Find the positions (row and column)
                for (int r = 0; r < rows; r++)
                {
                    for (int c = 0; c < cols; c++)
                    {
                        if (keyMatrix[r, c] == letter1)
                        {
                            row1 = r;
                            col1 = c;
                        }
                        else if (keyMatrix[r, c] == letter2)
                        {
                            row2 = r;
                            col2 = c;
                        }
                    }
                }

                if (row1 == row2)
                {
                    // Increment the column position by 1 and wrap around to 0 if it reaches the last column
                    col1 = (col1 + 1) % 5;
                    col2 = (col2 + 1) % 5;
                }
                else if (col1 == col2)
                {
                    // Increment the row position by 1 and wrap around to 0 if it reaches the last row
                    row1 = (row1 + 1) % 5;
                    row2 = (row2 + 1) % 5;
                }
                else
                {
                    // Different row and different column, swap columns and keep rows
                    int tmp = col1;
                    col1 = col2;
                    col2 = tmp;
                }

                cipherText += keyMatrix[row1, col1].ToString().ToUpper() + keyMatrix[row2, col2].ToString().ToUpper();
            }

            return cipherText;

        }
    }
}

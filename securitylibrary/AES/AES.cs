using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        #region Mix Column functions
        public static string[,] iMixColumn(string[,] stateArray)
        {
            string[,] result = new string[4, 4];

            for (int col = 0; col < 4; col++)
            {
                for (int row = 0; row < 4; row++)
                {
                    int value = 0;
                    for (int i = 0; i < 4; i++)
                    {
                        int stateVal = Convert.ToInt32(stateArray[i, col], 16);
                        int matrixVal = Convert.ToInt32(iMixColumnMatrix[row, i], 16);
                        int product = galoisMultiplication(stateVal, matrixVal);
                        value ^= product;
                    }
                    result[row, col] = value.ToString("X2");
                }
            }

            return result;
        }

        public static int galoisMultiplication(int a, int b)
        {
            int p = 0;
            for (int counter = 0; counter < 8; counter++)
            {
                if ((b & 1) != 0)
                {
                    p ^= a;
                }

                bool hiBitSet = (a & 0x80) != 0;
                a <<= 1;

                if (hiBitSet)
                {
                    a ^= 0x1b; 
                }

                b >>= 1;
            }
            return p;
        }
        #endregion

        #region S-Box and Inverse S-Box
        public static string[] SBOX = {
            "63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76",
            "CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0",
            "B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15",
            "04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75",
            "09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84",
            "53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF",
            "D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8",
            "51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2",
            "CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73",
            "60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB",
            "E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79",
            "E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08",
            "BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A",
            "70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E",
            "E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF",
            "8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16"
        };

        private static string[] iSBOX = {
            "52", "09", "6A", "D5", "30", "36", "A5", "38", "BF", "40", "A3", "9E", "81", "F3", "D7", "FB",
            "7C", "E3", "39", "82", "9B", "2F", "FF", "87", "34", "8E", "43", "44", "C4", "DE", "E9", "CB",
            "54", "7B", "94", "32", "A6", "C2", "23", "3D", "EE", "4C", "95", "0B", "42", "FA", "C3", "4E",
            "08", "2E", "A1", "66", "28", "D9", "24", "B2", "76", "5B", "A2", "49", "6D", "8B", "D1", "25",
            "72", "F8", "F6", "64", "86", "68", "98", "16", "D4", "A4", "5C", "CC", "5D", "65", "B6", "92",
            "6C", "70", "48", "50", "FD", "ED", "B9", "DA", "5E", "15", "46", "57", "A7", "8D", "9D", "84",
            "90", "D8", "AB", "00", "8C", "BC", "D3", "0A", "F7", "E4", "58", "05", "B8", "B3", "45", "06",
            "D0", "2C", "1E", "8F", "CA", "3F", "0F", "02", "C1", "AF", "BD", "03", "01", "13", "8A", "6B",
            "3A", "91", "11", "41", "4F", "67", "DC", "EA", "97", "F2", "CF", "CE", "F0", "B4", "E6", "73",
            "96", "AC", "74", "22", "E7", "AD", "35", "85", "E2", "F9", "37", "E8", "1C", "75", "DF", "6E",
            "47", "F1", "1A", "71", "1D", "29", "C5", "89", "6F", "B7", "62", "0E", "AA", "18", "BE", "1B",
            "FC", "56", "3E", "4B", "C6", "D2", "79", "20", "9A", "DB", "C0", "FE", "78", "CD", "5A", "F4",
            "1F", "DD", "A8", "33", "88", "07", "C7", "31", "B1", "12", "10", "59", "27", "80", "EC", "5F",
            "60", "51", "7F", "A9", "19", "B5", "4A", "0D", "2D", "E5", "7A", "9F", "93", "C9", "9C", "EF",
            "A0", "E0", "3B", "4D", "AE", "2A", "F5", "B0", "C8", "EB", "BB", "3C", "83", "53", "99", "61",
            "17", "2B", "04", "7E", "BA", "77", "D6", "26", "E1", "69", "14", "63", "55", "21", "0C", "7D"
        };
        #endregion

        public static string[,] constantRound = {
            { "01", "02", "04", "08", "10", "20", "40", "80", "1B", "36" },
            { "00", "00", "00", "00", "00", "00", "00", "00", "00", "00" },
            { "00", "00", "00", "00", "00", "00", "00", "00", "00", "00" },
            { "00", "00", "00", "00", "00", "00", "00", "00", "00", "00" }
        };

        #region MixColumns Inverse MixColumns
        public static string[,] mixColumnMatrix = {
            { "02", "03", "01", "01" },
            { "01", "02", "03", "01" },
            { "01", "01", "02", "03" },
            { "03", "01", "01", "02" }
        };

        public static string[,] iMixColumnMatrix = {
            { "0E", "0B", "0D", "09" },
            { "09", "0E", "0B", "0D" },
            { "0D", "09", "0E", "0B" },
            { "0B", "0D", "09", "0E" }
        };


        #endregion

        #region Number Representation
        static string BinXOR(string binary1, string binary2)
        {
            string res = "";
            if (binary1 != "" && binary2 != "")
            {
                for (int i = 0; i < 8; i++)
                    res += binary1[i] == binary2[i] ? '0' : '1';
            }
            else if (binary1 == "")
                res = binary2;
            else if (binary2 == "")
                res = binary1;
            return res;
        }
        static string HextoBin(string x)
        {
            x = Convert.ToString(Convert.ToInt32(x.ToString(), 16), 2).PadLeft(8, '0');
            return x;
        }
        static string BintoHex(string x)
        {
            x = Convert.ToString(Convert.ToInt32(x.ToString(), 2), 16);
            return x;
        }

        static String Shift_1B(string bin)//shift left and xor with 1B
        {
            if (bin[0] == '0')
            {
                return bin.Remove(0, 1) + "0";
            }
            else
            {
                return BinXOR((bin.Remove(0, 1) + "0"), HextoBin("1B"));
            }
        }
        #endregion

        #region Binary Multiplication
        static string _09(string bin)//bin×09=(((bin×2)×2)×2)+bin
        {
            string res = BinXOR(Shift_1B(Shift_1B(Shift_1B(bin))), bin);
            return res;
        }
        static string _0B(string bin)//bin×0B=((((bin×2)×2)+bin)×2)+bin
        {
            string res = BinXOR(Shift_1B(BinXOR(Shift_1B(Shift_1B(bin)), bin)), bin);
            return res;
        }
        static string _0D(string bin)//bin×0D=((((bin×2)+bin)×2)×2)+bin
        {
            string res = BinXOR(Shift_1B(Shift_1B(BinXOR(Shift_1B(bin), bin))), bin);
            return res;

        }
        static string _0E(string bin)//bin×0E=((((bin×2)+bin)×2)+bin)×2
        {
            string res = Shift_1B(BinXOR(Shift_1B(BinXOR(Shift_1B(bin), bin)), bin));
            return res;

        }
        #endregion
        private string[,] InvMixColumns(string[,] matrix)
        {
            string[,] mixed = { { "", "", "", "" }, { "", "", "", "" }, { "", "", "", "" }, { "", "", "", "" } };
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        StringBuilder binary1 = new StringBuilder(HextoBin(matrix[k, j]));
                        string res = "";
                        if (iMixColumnMatrix[i, k].Equals("09", StringComparison.OrdinalIgnoreCase))
                        {
                            res = _09(binary1.ToString());
                        }
                        else if (iMixColumnMatrix[i, k].Equals("0B", StringComparison.OrdinalIgnoreCase))
                        {
                            res = _0B(binary1.ToString());
                        }
                        else if (iMixColumnMatrix[i, k].Equals("0D", StringComparison.OrdinalIgnoreCase))
                        {
                            res = _0D(binary1.ToString());
                        }
                        else if (iMixColumnMatrix[i, k].Equals("0E", StringComparison.OrdinalIgnoreCase))
                        {
                            res = _0E(binary1.ToString());
                        }
                        mixed[i, j] = BinXOR(mixed[i, j].PadLeft(8, '0'), res);
                        if (k == 3)
                        {
                            mixed[i, j] = BintoHex(mixed[i, j]).PadLeft(2, '0').ToUpper();
                        }
                    }
                }
            }
            return mixed;
        }
        public struct hexToDecimal {
            public string hexa;
            public int deci;
        }
        public override string Decrypt(string cipherText, string key)
        {
            key = key.ToUpper();
            hexToDecimal[] hextodec = new hexToDecimal[6];
            hextodec[0] = new hexToDecimal { hexa = "A", deci = 10 };
            hextodec[1] = new hexToDecimal { hexa = "B", deci = 11 };
            hextodec[2] = new hexToDecimal { hexa = "C", deci = 12 };
            hextodec[3] = new hexToDecimal { hexa = "D", deci = 13 };
            hextodec[4] = new hexToDecimal { hexa = "E", deci = 14 };
            hextodec[5] = new hexToDecimal { hexa = "F", deci = 15 };

            int i, j, k, x, idx = 0, indx = 0, constIdx = 0;
            string tmp, nextTmp;

            string[,] initKeyMatrix = new string[4, 4];
            string[,] keyMatrix = new string[4, 4];
            string[] keyColumn = new string[4];

            string[,] SBOXMatrix = new string[16, 16];
            string[,] iSBOXMatrix = new string[16, 16];

            string[,] fullKeyMatrix = new string[4, 40];
            string[,] newFullKeyMatrix = new string[4, 44];
            string[,] updatedKeyMatrix = new string[4, 4];
            string[,] stateArray = new string[4, 4];
            string[,] plainMatrix = new string[4, 4];
            string[,] prevStateArray = new string[4, 4];
            string cipher = "";
            string[] cipherArr = new string[cipherText.Length];
            string[,] mulMatrix = new string[4, 4];
            string[,] trans = new string[4, 4];


            for (i = 0; i < 4; i++)
            {
                for (j = 0; j < 4; j++)
                {
                    keyMatrix[j, i] = key.Substring(idx + 2, 2);
                    initKeyMatrix[j, i] = key.Substring(idx + 2, 2);
                    idx += 2;
        
                }
            }
            #region Key Expansion
            // Key Expansion
            for (k = 0; k < 10; k++)
            {

                for (i = 0; i < 4; i++)
                {
                    keyColumn[i] = keyMatrix[i, 3];
                }

                // Column Rotation
                idx = 3;
                nextTmp = keyColumn[3];
                for (i = 3; i >= 0; i--)
                {
                    idx = i;
                    if (idx - 1 < 0)
                        idx = 4 - ((i - 1) * -1) % 4;
                    else
                        idx = i - 1;
                    tmp = keyColumn[idx];
                    keyColumn[idx] = nextTmp;
                    nextTmp = tmp;
                }



                idx = 0;
                for (i = 0; i < 16; i++)
                {
                    for (j = 0; j < 16; j++)
                    {
                        SBOXMatrix[i, j] = SBOX[idx];
                        iSBOXMatrix[i, j] = iSBOX[idx];
                        idx++;
                    }
                }

                string ind1, ind2;
                int idx1 = 0, idx2 = 0;

                for (i = 0; i < 4; i++)
                {
                    idx1 = 0;
                    idx2 = 0;

                    ind1 = keyColumn[i].Substring(0, 1);
                    ind2 = keyColumn[i].Substring(1, 1);

                    for (j = 0; j < 6; j++)
                    {
                        if (ind1 == hextodec[j].hexa)
                            idx1 = hextodec[j].deci;
                        if (ind2 == hextodec[j].hexa)
                            idx2 = hextodec[j].deci;

                    }

                    if (idx1 == 0)
                        idx1 = int.Parse(ind1);
                    if (idx2 == 0)
                        idx2 = int.Parse(ind2);

                    idx1 = idx1 % 16;
                    idx2 = idx2 % 16;

                    keyColumn[i] = SBOXMatrix[idx1, idx2];

                }
                int hex1, hex2, newXORValue;

                for (i = 0; i < 4; i++)
                {
                    hex1 = Convert.ToInt32(keyColumn[i], 16);
                    hex2 = Convert.ToInt32(constantRound[i, constIdx], 16);
                    newXORValue = hex1 ^ hex2;
                    keyColumn[i] = newXORValue.ToString("X");

                    if (keyColumn[i].Length == 1)
                        keyColumn[i] = "0" + keyColumn[i];
                }
                constIdx++;



                int XORValue;
                for (i = 0; i < 4; i++)
                {
                    for (j = 0; j < 4; j++)
                    {
                        if (i == 0)
                        {
                            XORValue = (Convert.ToInt32(keyColumn[j], 16)) ^ (Convert.ToInt32(keyMatrix[j, 0], 16));
                            updatedKeyMatrix[j, i] = XORValue.ToString("X");
                        }
                        else
                        {
                            XORValue = (Convert.ToInt32(updatedKeyMatrix[j, i - 1], 16)) ^ (Convert.ToInt32(keyMatrix[j, i], 16));
                            updatedKeyMatrix[j, i] = XORValue.ToString("X");
                        }
                        if (updatedKeyMatrix[j, i].Length == 1)
                            updatedKeyMatrix[j, i] = "0" + updatedKeyMatrix[j, i];
                        fullKeyMatrix[j, indx] = updatedKeyMatrix[j, i];
                    }
                    indx++;
                }
                for (i = 0; i < 4; i++)
                {
                    for (j = 0; j < 4; j++)
                    {
                        keyMatrix[j, i] = updatedKeyMatrix[j, i];

                    }
                }

                if (indx == 40)
                    break;
            }
            #endregion


            // Adding the initial key to W (Forming the Full Expanded Key Matrix)
            int flag = 0, c = 0, indexx = 0;
            for (i = 0; i < 40; i++)
            {

                for (j = 0; j < 4; j++)
                {
                    if (i < 4 && flag == 0)
                    {
                        newFullKeyMatrix[j, indexx] = initKeyMatrix[j, i];
                    }
                    else
                    {
                        c++;
                        if (c == 1)
                        {
                            flag = 1;
                            i = 0;
                        }
                            newFullKeyMatrix[j, indexx] = fullKeyMatrix[j, i];
                    }

                }

                indexx++;
            }
            ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            cipherText = cipherText.ToUpper();
            idx = 0;
            for (i = 0; i < 4; i++)
            {
                for (j = 0; j < 4; j++)
                {
                    plainMatrix[j, i] = cipherText.Substring(idx + 2, 2);
                    idx += 2;
                }
            }

            // State Array (last 4 words XOR ciphertext)
            int stateXORValue;
            int indxx = 40;
            for (i = 0; i < 4; i++)
            {
                for (j = 0; j < 4; j++)
                {
                    stateXORValue = (Convert.ToInt32(plainMatrix[j, i], 16)) ^ (Convert.ToInt32(newFullKeyMatrix[j,indxx], 16));
                    stateArray[j, i] = stateXORValue.ToString("X");

                    if (stateArray[j, i].Length == 1)
                        stateArray[j, i] = "0" + stateArray[j, i];
                }
                indxx++;
            }

            indxx = 39;

            for (i = 0; i < 4; i++)
            {
                for (j = 0; j < 4; j++)
                {
                    prevStateArray[j, i] = stateArray[j, i];
                }
            }

            for (x = 0; x < 10; x++)
            {
                #region SBOX
                // Byte Substitution (SBOX)
                string ind1_1, ind2_1;
                int idx1_1 = 0, idx2_1 = 0;

                for (i = 0; i < 4; i++)
                {
                    for (j = 0; j < 4; j++)
                    {
                        idx1_1 = 0;
                        idx2_1 = 0;

                        ind1_1 = prevStateArray[j, i].Substring(0, 1);
                        ind2_1 = prevStateArray[j, i].Substring(1, 1);

                        for (k = 0; k < 6; k++)
                        {
                            if (ind1_1 == hextodec[k].hexa)
                                idx1_1 = hextodec[k].deci;
                            if (ind2_1 == hextodec[k].hexa)
                                idx2_1 = hextodec[k].deci;

                        }

                        if (idx1_1 == 0)
                            idx1_1 = int.Parse(ind1_1);
                        if (idx2_1 == 0)
                            idx2_1 = int.Parse(ind2_1);

                        idx1_1 = idx1_1 % 16;
                        idx2_1 = idx2_1 % 16;

                        prevStateArray[j, i] = iSBOXMatrix[idx1_1, idx2_1];
                       // Console.WriteLine(prevStateArray[j, i]);
                    }

                }
                #endregion 

                Console.WriteLine($"\nround {x}^\n");

                #region Shift Rows Right
                // Shift Rows
                string tmp_1, nextTmp_1;
                idx = 0;
                int flag1 = 0, flag2 = 0, count = 0;
        
                for (i = 1; i < 4; i++)
                {
                    if (i == 2)
                    {
                        count++;
                        if (count > 1)
                            flag1 = 1;
                    }
                    else if (i == 3)
                    {
                        count++;
                        if (count > 2)
                            flag2 = 1;
                    }
                    nextTmp_1 = prevStateArray[i, 3];
                    for (j = 0; j < 4; j++)
                    {
                        idx = j;
                        if (idx + 1 > 4)

                            idx = (idx + 1) % 4;
                 
                        tmp_1 = prevStateArray[i, idx];
                        prevStateArray[i, idx] = nextTmp_1;
                        nextTmp_1 = tmp_1;
                    }
                    
                    if (i == 2 && count > 1 && flag1 == 1)
                    {
                        flag1 = 0;
                        count = 0;
                    }
                    else if (i == 2 && flag1 == 0)
                        i = 1;
                    if (i == 3 && count > 2 && flag2 == 1)
                        flag2 = 0;
                    else if (i == 3 && flag2 == 0)
                        i = 2;
                }
                #endregion
                int z, w;
                for( z = 0; z < 4; z++)
                {
                    for ( w = 0; w < 4; w++)
                    {

                        Console.WriteLine($"shift row: {prevStateArray[z, w]}");
                    }
                }

                // ADD Round Key
                Console.WriteLine("\nround key:\n");
                int XOR;
                for (i = 0; i < 4; i++)
                {
                    int b = indxx - 3;
                    for (j = 0; j < 4; j++)
                    {
                        XOR = (Convert.ToInt32(prevStateArray[j, i], 16)) ^ (Convert.ToInt32(newFullKeyMatrix[j, b + i], 16));
                        mulMatrix[j, i] = XOR.ToString("X");

                        if (mulMatrix[j, i].Length == 1)
                            mulMatrix[j, i] = "0" + mulMatrix[j, i];
                        //Console.WriteLine(newFullKeyMatrix[j, b + i]);
                    }
                }
                indxx -= 4;

                if (x == 9)
                {
                    for (i = 0; i < 4; i++)
                    {
                        for (j = 0; j < 4; j++)
                        {
                            prevStateArray[j, i] = mulMatrix[j, i];
                        }
                    }
                }
                else
                {

                    #region Mix Columns
                    //Mix Columns
                    // Matrix multiplication

                    prevStateArray = InvMixColumns(mulMatrix);

                    for (z = 0; z < 4; z++)
                    {
                        for (w = 0; w < 4; w++)
                        {
                           Console.WriteLine($"mix : {mulMatrix[z, w]}");
                        }
                    }
                    #endregion
                }

            }

            char[] plainChar = new char[plainMatrix.Length];
            string PT;
            idx = 0;
            for (i = 0; i < 4; i++)
            {
                for (j = 0; j < 4; j++)
                {
                    cipherArr[idx] = prevStateArray[j, i];
                    cipher += cipherArr[idx];
                    idx++;
                }
            }
            PT = "0x" + cipher;

            Console.WriteLine(PT);

            return (PT);
        }

        public override string Encrypt(string plainText, string key)
        {
            key = key.ToUpper();
            hexToDecimal[] hextodec = new hexToDecimal[6];
            hextodec[0] = new hexToDecimal { hexa = "A", deci = 10 };
            hextodec[1] = new hexToDecimal { hexa = "B", deci = 11 };
            hextodec[2] = new hexToDecimal { hexa = "C", deci = 12 };
            hextodec[3] = new hexToDecimal { hexa = "D", deci = 13 };
            hextodec[4] = new hexToDecimal { hexa = "E", deci = 14 };
            hextodec[5] = new hexToDecimal { hexa = "F", deci = 15 };

            int i, j, k, x, idx = 0, indx = 0, constIdx = 0, fullKeyCnt = 0;
            string tmp, nextTmp;
            int mixColCnt = 0;

            string[,] initKeyMatrix = new string[4, 4];
            string[,] keyMatrix = new string[4, 4];
            string[] keyColumn = new string[4];
            string[,] SBOXMatrix = new string[16, 16];
            string[,] fullKeyMatrix = new string[4, 40];
            string[,] updatedKeyMatrix = new string[4, 4];
            string[,] stateArray = new string[4, 4];
            string[,] plainMatrix = new string[4, 4];
            string[,] prevStateArray = new string[4, 4];
            string cipher = "";
            string[] cipherArr = new string[plainText.Length];
            string[,] mulMatrix = new string[4, 4];


            for (i = 0; i < 4; i++)
            {
                for (j = 0; j < 4; j++)
                {
                    keyMatrix[j, i] = key.Substring(idx + 2, 2);
                    initKeyMatrix[j, i] = key.Substring(idx + 2, 2);
                    idx += 2;
                }
            }

            // Key Expansion
            for (k = 0; k < 10; k++)
            {

                for (i = 0; i < 4; i++)
                {
                    keyColumn[i] = keyMatrix[i, 3];
                }

                idx = 3;
                nextTmp = keyColumn[3];
                for (i = 3; i >= 0; i--)
                {
                    idx = i;
                    if (idx - 1 < 0)
                        idx = 4 - ((i - 1) * -1) % 4;
                    else
                        idx = i - 1;
                    tmp = keyColumn[idx];
                    keyColumn[idx] = nextTmp;
                    nextTmp = tmp;
                }



                idx = 0;
                for (i = 0; i < 16; i++)
                {
                    for (j = 0; j < 16; j++)
                    {
                        SBOXMatrix[i, j] = SBOX[idx];
                        idx++;
                    }
                }

                string ind1, ind2;
                int idx1 = 0, idx2 = 0;

                for (i = 0; i < 4; i++)
                {
                    idx1 = 0;
                    idx2 = 0;

                    ind1 = keyColumn[i].Substring(0, 1);
                    ind2 = keyColumn[i].Substring(1, 1);

                    for (j = 0; j < 6; j++)
                    {
                        if (ind1 == hextodec[j].hexa)
                            idx1 = hextodec[j].deci;
                        if (ind2 == hextodec[j].hexa)
                            idx2 = hextodec[j].deci;

                    }

                    if (idx1 == 0)
                        idx1 = int.Parse(ind1);
                    if (idx2 == 0)
                        idx2 = int.Parse(ind2);

                    idx1 = idx1 % 16;
                    idx2 = idx2 % 16;

                    keyColumn[i] = SBOXMatrix[idx1, idx2];
                    
                }
                int hex1, hex2, newXORValue;
                
                for (i = 0; i < 4; i++)
                {
                    hex1 = Convert.ToInt32(keyColumn[i], 16);
                    hex2 = Convert.ToInt32(constantRound[i,constIdx], 16);
                    newXORValue = hex1 ^ hex2;
                    keyColumn[i] = newXORValue.ToString("X");

                    if (keyColumn[i].Length == 1)
                        keyColumn[i] = "0" + keyColumn[i];
                }
                constIdx++;
     


                int XORValue;
                for (i = 0; i < 4; i++)
                {
                    for (j = 0; j < 4; j++)
                    {
                        if (i == 0)
                        {
                            XORValue = (Convert.ToInt32(keyColumn[j], 16)) ^ (Convert.ToInt32(keyMatrix[j, 0], 16));
                            updatedKeyMatrix[j, i] = XORValue.ToString("X");
                        }
                        else
                        {
                            XORValue = (Convert.ToInt32(updatedKeyMatrix[j, i - 1], 16)) ^ (Convert.ToInt32(keyMatrix[j, i], 16));
                            updatedKeyMatrix[j, i] = XORValue.ToString("X");
                        }
                        if (updatedKeyMatrix[j, i].Length == 1)
                            updatedKeyMatrix[j, i] = "0" + updatedKeyMatrix[j, i];
                        fullKeyMatrix[j, indx] = updatedKeyMatrix[j, i];
                    }
                    indx++;
                }
                for (i = 0; i < 4; i++)
                {
                    for (j = 0; j < 4; j++)
                    {
                        keyMatrix[j, i] = updatedKeyMatrix[j, i];

                    }
                }

                if (indx == 40)
                     break; 
            }
//----------------------------------------------------Cipher Text generation-------------------------------------------------------------------//
            plainText = plainText.ToUpper();
            idx = 0;
            for (i = 0; i < 4; i++)
            {
                for (j = 0; j < 4; j++)
                {
                    plainMatrix[j, i] = plainText.Substring(idx + 2, 2);
                    idx += 2;
                }
            }

            // State Array (initial key matrix XOR plaintext)
            int stateXORValue;
            idx = 0;
            for (i = 0; i < 4; i++)
            {
                for (j = 0; j < 4; j++)
                {
                    stateXORValue = (Convert.ToInt32(plainMatrix[j, i], 16)) ^ (Convert.ToInt32(initKeyMatrix[j, i], 16));
                    stateArray[j, i] = stateXORValue.ToString("X");
                
                if (stateArray[j, i].Length == 1)
                    stateArray[j, i] = "0" + stateArray[j, i];
                }
            }

            for (i = 0; i < 4; i++)
            {
                for (j = 0; j < 4; j++)
                {
                    prevStateArray[j, i] = stateArray[j, i];
                }
            }
            //----------------------------------------------------------------------------------------------------------------------------//
            
            for (x = 0; x < 10; x++)
            {
                mixColCnt++;
                // Byte Substitution (SBOX)
                string ind1_1, ind2_1;
                int idx1_1 = 0, idx2_1 = 0;

                for (i = 0; i < 4; i++)
                {
                    for (j = 0; j < 4; j++)
                    {
                        idx1_1 = 0;
                        idx2_1 = 0;

                        ind1_1 = prevStateArray[j, i].Substring(0, 1);
                        ind2_1 = prevStateArray[j, i].Substring(1, 1);

                        for (k = 0; k < 6; k++)
                        {
                            if (ind1_1 == hextodec[k].hexa)
                                idx1_1 = hextodec[k].deci;
                            if (ind2_1 == hextodec[k].hexa)
                                idx2_1 = hextodec[k].deci;

                        }

                        if (idx1_1 == 0)
                            idx1_1 = int.Parse(ind1_1);
                        if (idx2_1 == 0)
                            idx2_1 = int.Parse(ind2_1);

                        idx1_1 = idx1_1 % 16;
                        idx2_1 = idx2_1 % 16;

                        prevStateArray[j, i] = SBOXMatrix[idx1_1, idx2_1];
                    }

                }

                // Shift Rows
                string tmp_1, nextTmp_1;
                idx = 3;
                int flag1 = 0, flag2 = 0, count = 0;
                nextTmp_1 = prevStateArray[1, 3];
                for (i = 1; i < 4; i++)
                {
                    if (i == 2)
                    {
                        count++;
                        if (count > 1)
                            flag1 = 1;
                    }
                    else if (i == 3)
                    {
                        count++;
                        if (count > 2)
                            flag2 = 1;
                    }
                    nextTmp_1 = prevStateArray[i, 3];
                    for (j = 3; j >= 0; j--)
                    {
                        idx = j;
                        if (idx - 1 < 0)

                            idx = 4 - ((j - 1) * -1) % 4;
                        else
                            idx = j - 1;
                        tmp_1 = prevStateArray[i, idx];
                        prevStateArray[i, idx] = nextTmp_1;
                        nextTmp_1 = tmp_1;
                       
                    }

                    if (i == 2 && count > 1 && flag1 == 1)
                    {
                        flag1 = 0;
                        count = 0;
                    }
                    else if (i == 2 && flag1 == 0)
                        i = 1;
                    if (i == 3 && count > 2 && flag2 == 1)
                        flag2 = 0;
                    else if (i == 3 && flag2 == 0)
                        i = 2;
                }

                if (x == 9)
                {
                    for (i = 0; i < 4; i++)
                    {
                        for (j = 0; j < 4; j++)
                        {
                            mulMatrix[j, i] = prevStateArray[j, i];
                        }
                    }
                }
                else
                {
                    //Mix Columns
                    // Matrix multiplication
                    int sum = 0;

                    for (i = 0; i < 4; i++)
                    {
                        for (j = 0; j < 4; j++)
                        {
                            sum = 0;

                            for (k = 0; k < 4; k++)
                            {
                                int mixValue = int.Parse(mixColumnMatrix[j, k], System.Globalization.NumberStyles.HexNumber);

                                int stateValue = int.Parse(prevStateArray[k, i], System.Globalization.NumberStyles.HexNumber);

                                int multiplied;
                                if (mixValue == 1)
                                {
                                    multiplied = stateValue;
                                }
                                else if (mixValue == 2)
                                {
                                    multiplied = (stateValue << 1) ^ ((stateValue & 0x80) == 0x80 ? 0x1B : 0);
                                }
                                else // mixValue == 3
                                {
                                    multiplied = ((stateValue << 1) ^ ((stateValue & 0x80) == 0x80 ? 0x1B : 0)) ^ stateValue;
                                }

                                sum ^= multiplied;

                            }
                            // Format as a two-digit hexadecimal string
                            mulMatrix[j, i] = (sum.ToString("X2")); 
                            if (mulMatrix[j, i].Length > 2)
                                mulMatrix[j, i] = (sum.ToString("X2")).Substring(1, 2);
                        }
                    }
                }

                int XOR;
                for (i = 0; i < 4; i++)
                {
                    for (j = 0; j < 4; j++)
                    {
                        XOR = (Convert.ToInt32(mulMatrix[j, i], 16)) ^ (Convert.ToInt32(fullKeyMatrix[j, fullKeyCnt], 16));
                        prevStateArray[j, i] = XOR.ToString("X");

                        if (prevStateArray[j, i].Length == 1)
                            prevStateArray[j, i] = "0" + prevStateArray[j, i];
                    }
                    fullKeyCnt++;
                }
            }

            char[] cipherChar = new char[plainMatrix.Length];
            idx = 0;
            for (i = 0; i < 4; i++)
            {
                for (j = 0; j < 4; j++)
                {
                    cipherArr[idx] = prevStateArray[j, i];
                    cipher += cipherArr[idx];
                    idx++;
                }
            }
            cipher = "0x" + cipher;

            return (cipher);
        }
    }
}

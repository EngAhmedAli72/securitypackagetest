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
        public static string[,] keyyy =
        {
        {"2b","28","ab","09" },
        {"7e","ae","f7","cf" },
        {"15","d2","15","4f" },
        {"16","a6","88","3c" }

        };
        //public static string[,] inkeyyy =
        //{
        //{"a0","88","23","2a" },
        //{"fa","54","a3","6c" },
        //{"fe","2c","39","76" },
        //{"17","b1","39","05" }

        //};

        public static string[,] inkeyyy =
        {
        {"f2","7a","59","73" },
        {"c2","96","35","59" },
        {"95","b9","80","f6" },
        {"f2","43","7a","7f" }

        };
        public static string[,] test =
        {
        {"a4","68","6b","02" },
        {"9c","9f","5b","6a" },
        {"7f","35","ea","50" },
        {"f2","2b","43","49" }

        };
        public static string[,] nextKey;


        public static byte[,] inverseSBox =  {
            //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
            { 0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB }, //0
            { 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB }, //1
            { 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E }, //2
            { 0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25 }, //3
            { 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92 }, //4
            { 0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84 }, //5
            { 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06 }, //6
            { 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B }, //7
            { 0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73 }, //8
            { 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E }, //9
            { 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B }, //A
            { 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4 }, //B
            { 0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F }, //C
            { 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF }, //D
            { 0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61 }, //E
            { 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D }  //F
        };

        public static byte[,] S_Box =
        {
          //   0     1     2     3     4     5     6     7     8      9    A     B      C    D     E    F  
            {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},//0
            {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},//1
            {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},//2
            {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},//3
            {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},//4
            {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},//5
            {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},//6
            {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},//7
            {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},//8
            {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},//9
            {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},//A
            {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},//B
            {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},//C
            {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},//D
            {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},//E
            {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16} //F
        };

        public static byte[,] Rcon =
        {
            {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36 },
            {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
            {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
            {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 }

        };

        public static byte[,] InverseRcon =
        {
            {0x36,0x1b,0x80,0x40,0x20,0x10,0x08,0x04,0x02,0x01 },
            {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
            {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
            {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 }

        };

        public static byte[,] galiosMatrix =
        {
            {0x02,0x03,0x01,0x01},
            {0x01,0x02,0x03,0x01},
            {0x01,0x01,0x02,0x03},
            {0x03,0x01,0x01,0x02},
        };

        public static byte[,] inverseGaliosMatrix =
        {
            {0x0e,0x0b,0x0d,0x09},
            {0x09,0x0e,0x0b,0x0d},
            {0x0d,0x09,0x0e,0x0b},
            {0x0b,0x0d,0x09,0x0e},
        };

        public string[,] GetPlainTextMatrix(string plainText)
        {

            int i = 2;
            string[,] PlainTextMatrix = new string[4, 4];

            //Create PlainText Matrix
            for (int ColmIndex = 0; ColmIndex < 4; ColmIndex++)
            {

                for (int RowIndex = 0; RowIndex < 4; RowIndex++)
                {
                    PlainTextMatrix[RowIndex, ColmIndex] = $"{plainText.ElementAt(i)}{plainText.ElementAt(i + 1)}";
                    i += 2;

                }
            }
            return PlainTextMatrix;
        }
        public string[,] SubByte(string[,] Matrix)
        {
            string[,] SubByteMatrix = new string[4, 4];
            int RowIndex = 0, ColmIndex = 0;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    //get index from sBox
                    if (Matrix[i, j].Length < 2)
                    {
                        RowIndex = 0;
                        ColmIndex = Convert.ToInt32(Matrix[i, j].ElementAt(0).ToString(), 16);
                    }
                    else
                    {
                        RowIndex = Convert.ToInt32(Matrix[i, j].ElementAt(0).ToString(), 16);
                        ColmIndex = Convert.ToInt32(Matrix[i, j].ElementAt(1).ToString(), 16);
                    }
                    //replace Value
                    SubByteMatrix[i, j] = S_Box[RowIndex, ColmIndex].ToString("x");

                }
            }
            return SubByteMatrix;
        }


        public string[,] shiftRows(string[,] matrix)
        {
            for (int i = 1; i < 4; i++)
            {
                for (int j = 0; j < i; j++)
                {
                    string temp = matrix[i, 0];
                    matrix[i, 0] = matrix[i, 1];
                    matrix[i, 1] = matrix[i, 2];
                    matrix[i, 2] = matrix[i, 3];
                    matrix[i, 3] = temp;
                }
            }
            return matrix;
        }
        public static byte GMul(byte a, byte b)
        {
            byte p = 0;
            byte counter;
            byte hi_bit_set;
            for (counter = 0; counter < 8; counter++)
            {
                if ((b & 1) != 0)
                {
                    p ^= a;
                }
                hi_bit_set = (byte)(a & 0x80);
                a <<= 1;
                if (hi_bit_set != 0)
                {
                    a ^= 0x1b;
                }
                b >>= 1;
            }
            return p;
        }

        public static string[,] mixColumns(string[,] matrix)
        {
            string[,] newMatrix = new string[4, 4];
            byte[,] temp = new byte[4, 4];
            // convert matrix from string to byte
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    temp[i, j] = Convert.ToByte(matrix[i, j], 16);
                }
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {

                    var decimalNumber =
                        GMul(galiosMatrix[j, 0], temp[0, i])
                        ^ GMul(galiosMatrix[j, 1], temp[1, i])
                        ^ GMul(galiosMatrix[j, 2], temp[2, i])
                        ^ GMul(galiosMatrix[j, 3], temp[3, i]);
                    string hex = decimalNumber.ToString("x");
                    newMatrix[j, i] = hex;
                }
            }
            return newMatrix;

        }

        public static string[,] InvesreMixColumns(string[,] matrix)
        {
            string[,] newMatrix = new string[4, 4];
            byte[,] temp = new byte[4, 4];
            // convert matrix from string to byte
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    temp[i, j] = Convert.ToByte(matrix[i, j], 16);
                }
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {

                    var decimalNumber =
                        GMul(inverseGaliosMatrix[j, 0], temp[0, i])
                        ^ GMul(inverseGaliosMatrix[j, 1], temp[1, i])
                        ^ GMul(inverseGaliosMatrix[j, 2], temp[2, i])
                        ^ GMul(inverseGaliosMatrix[j, 3], temp[3, i]);
                    string hex = decimalNumber.ToString("x");
                    newMatrix[j, i] = hex;
                }
            }
            return newMatrix;

        }


        public static string[,] KeySchedule(string[,] key, int indexRcon)
        {
            string[,] keySchedual = new string[4, 4];
            string[,] lastCol = new string[4, 1];

            //Rotate column
            for (int i = 0; i < 4; i++)
            {
                lastCol[i, 0] = key[(i + 1) % 4, 3];
            }

            //SubBytes
            int RowIndex = 0, ColmIndex = 0;
            for (int i = 0; i < 4; i++)
            {
                if (lastCol[i, 0].Length < 2)
                {
                    RowIndex = 0;
                    ColmIndex = Convert.ToInt32(lastCol[i, 0].ElementAt(0).ToString(), 16);
                }
                else
                {
                    RowIndex = Convert.ToInt32(lastCol[i, 0].ElementAt(0).ToString(), 16);
                    ColmIndex = Convert.ToInt32(lastCol[i, 0].ElementAt(1).ToString(), 16);
                }
                lastCol[i, 0] = S_Box[RowIndex, ColmIndex].ToString("x");
            }


            //Generate first column
            for (int i = 0; i < 4; i++)
            {
                keySchedual[i, 0] = (Convert.ToByte(key[i, 0], 16) ^ Convert.ToByte(lastCol[i, 0], 16) ^ Rcon[i, indexRcon]).ToString("x");
            }


            //Generate the complete matrix
            for (int col = 1; col < 4; col++)
            {
                for (int row = 0; row < 4; row++)
                {
                    keySchedual[row, col] = (Convert.ToByte(keySchedual[row, col - 1], 16) ^ Convert.ToByte(key[row, col], 16)).ToString("x");
                }

            }

            return keySchedual;
        }

        public static string[,] addRoundKey(string[,] state, ref string[,] key, int numOfRound, int index)
        {
            string[,] newMatrix = new string[4, 4];

            if (index != 0)
                key = KeySchedule(key, numOfRound);

            //apllay Xor Between two Matrices
            for (int ColmIndex = 0; ColmIndex < 4; ColmIndex++)
            {
                for (int RowIndex = 0; RowIndex < 4; RowIndex++)
                {
                    newMatrix[RowIndex, ColmIndex] = (Convert.ToInt32(state[RowIndex, ColmIndex], 16) ^
                        Convert.ToInt32(key[RowIndex, ColmIndex], 16)).ToString("x");
                }
            }
            return newMatrix;



        }


        // inverse Round Key 
        public static string[,] InverseAddRoundKey(string[,] state, ref string[,] key, int numOfRound, int index)
        {
            string[,] oldMatrix = new string[4, 4];

            for (int ColmIndex = 0; ColmIndex < 4; ColmIndex++)
            {
                for (int RowIndex = 0; RowIndex < 4; RowIndex++)
                {
                    oldMatrix[RowIndex, ColmIndex] = (Convert.ToInt32(state[RowIndex, ColmIndex], 16) ^
                        Convert.ToInt32(key[RowIndex, ColmIndex], 16)).ToString("x");
                }
            }
            if (index != 0)
                key = InverseKeySchedule(key, numOfRound);
            return oldMatrix;
        }
        // inverse shift rows
        public static string[,] InverseShiftRows(string[,] matrix)
        {
            for (int row = 1; row < matrix.GetLength(0); row++)
            {
                for (int i = 0; i < row; i++)
                {
                    string tmp = matrix[row, 3];
                    matrix[row, 3] = matrix[row, 2];
                    matrix[row, 2] = matrix[row, 1];
                    matrix[row, 1] = matrix[row, 0];
                    matrix[row, 0] = tmp;
                }
            }
            return matrix;
        }

        //inverse subBytes
        public string[,] InverseSubByte(string[,] Matrix)
        {
            string[,] matrix = new string[4, 4];
            int RowIndex = 0, ColmIndex = 0;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    //get index from inverseSBox
                    if (Matrix[i, j].Length < 2)
                    {
                        RowIndex = 0;
                        ColmIndex = Convert.ToInt32(Matrix[i, j].ElementAt(0).ToString(), 16);
                    }
                    else
                    {
                        RowIndex = Convert.ToInt32(Matrix[i, j].ElementAt(0).ToString(), 16);
                        ColmIndex = Convert.ToInt32(Matrix[i, j].ElementAt(1).ToString(), 16);
                    }
                    //replace Value
                    matrix[i, j] = inverseSBox[RowIndex, ColmIndex].ToString("x");

                }
            }
            return matrix;
        }

        // Inverse Key Schedule
        public static string[,] InverseKeySchedule(string[,] key, int indexRcon)
        {
            string[,] inverseKeySchedual = new string[4, 4];
            string[,] lastCol = new string[4, 1];

            //Generate the last three column
            for (int col = 3; col > 0; col--)
            {
                for (int row = 0; row < 4; row++)
                {
                    inverseKeySchedual[row, col] = (Convert.ToByte(key[row, col - 1], 16) ^ Convert.ToByte(key[row, col], 16)).ToString("x");
                }

            }
            for (int i = 0; i < 4; i++)
            {
                lastCol[i, 0] = inverseKeySchedual[(i + 1) % 4, 3];
            }

            //SubBytes
            int RowIndex = 0, ColmIndex = 0;
            for (int i = 0; i < 4; i++)
            {
                if (lastCol[i, 0].Length < 2)
                {
                    RowIndex = 0;
                    ColmIndex = Convert.ToInt32(lastCol[i, 0].ElementAt(0).ToString(), 16);
                }
                else
                {
                    RowIndex = Convert.ToInt32(lastCol[i, 0].ElementAt(0).ToString(), 16);
                    ColmIndex = Convert.ToInt32(lastCol[i, 0].ElementAt(1).ToString(), 16);
                }
                lastCol[i, 0] = S_Box[RowIndex, ColmIndex].ToString("x");
            }
            //Generat first column
            for (int i = 0; i < 4; i++)
            {
                inverseKeySchedual[i, 0] = (Convert.ToByte(key[i, 0], 16) ^ Convert.ToByte(lastCol[i, 0], 16) ^ Rcon[i, indexRcon]).ToString("x");
            }

            return inverseKeySchedual;
        }
        public override string Decrypt(string cipherText, string key)
        {



            //convert text to mat
            string[,] stateText = GetPlainTextMatrix(cipherText);
            string[,] cipherKey = GetPlainTextMatrix(key);
            string[,] temp = new string[4, 4];


            for (int i = 0; i < 10; i++)
            {
                cipherKey = KeySchedule(cipherKey, i);
            }


            temp = InverseAddRoundKey(stateText, ref cipherKey, 9, 1);
            temp = InverseShiftRows(temp);
            temp = InverseSubByte(temp);

            //first round


            //  main rounds
            for (int i = 8; i >= 0; i--)
            {
                temp = InverseAddRoundKey(temp, ref cipherKey, i, 1);
                temp = InvesreMixColumns(temp);
                temp = InverseShiftRows(temp);
                temp = InverseSubByte(temp);
            }
            //final round
            temp = InverseAddRoundKey(temp, ref cipherKey, 0, 0);
            //store cipher text in string 
            string plainText = "";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    if (temp[j, i].Length < 2)
                        plainText += "0";
                    plainText += temp[j, i].ToUpper();
                }

            }
            plainText = "0x" + plainText;

            return plainText;
        }

        public override string Encrypt(string plainText, string key)
        {
            //get number of rounds
            int keySize = Convert.ToInt32((key.Length - 2) / 2);
            int numOfRound;
            if (keySize == 16)
                numOfRound = 10;
            else if (keySize == 24)
                numOfRound = 12;
            else
                numOfRound = 14;

            //convert text to mat
            string[,] stateText = GetPlainTextMatrix(plainText);
            string[,] cipherKey = GetPlainTextMatrix(key);
            string[,] temp = new string[4, 4];

            //initial round
            temp = addRoundKey(stateText, ref cipherKey, 0, 0);

            //  main rounds
            for (int i = 0; i < numOfRound - 1; i++)
            {
                temp = SubByte(temp);
                temp = shiftRows(temp);
                temp = mixColumns(temp);
                temp = addRoundKey(temp, ref cipherKey, i, 1);
            }
            //final round
            temp = SubByte(temp);
            temp = shiftRows(temp);
            temp = addRoundKey(temp, ref cipherKey, 9, 1);

            //store cipher text in string 
            string cipherText = "";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    if (temp[j, i].Length < 2)
                        cipherText += "0";
                    cipherText += temp[j, i].ToUpper();
                }

            }
            cipherText = "0x" + cipherText;
            return cipherText;
        }
    }
}

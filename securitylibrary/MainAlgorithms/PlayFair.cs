using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            //incript
            char[,] Matrix = new char[5, 5];
            Matrix = CreateMatrix(key);
            int prev_char_row = 0, Prev_char_Col = 0, Next_char_row = 0, Next_char_Col = 0;
            string returnedText = "";
            //Start Decript
            for (int i = 0; i < cipherText.Length - 1; i += 2)
            {
                //get the indexs of each char
                for (int RowIndex = 0; RowIndex < 5; RowIndex++)
                {
                    for (int ColomeIndex = 0; ColomeIndex < 5; ColomeIndex++)
                    {
                        if (cipherText[i] == Matrix[RowIndex, ColomeIndex])
                        {
                            prev_char_row = RowIndex;
                            Prev_char_Col = ColomeIndex;
                        }
                        if (cipherText[i + 1] == Matrix[RowIndex, ColomeIndex])
                        {
                            Next_char_row = RowIndex;
                            Next_char_Col = ColomeIndex;
                        }


                    }

                }
                //start incript 
                if (prev_char_row == Next_char_row)
                {
                    if (Prev_char_Col == 0)
                        Prev_char_Col = 5;
                    if (Next_char_Col == 0)
                        Next_char_Col = 5;
                    returnedText += Matrix[prev_char_row, (Prev_char_Col - 1)];
                    returnedText += Matrix[Next_char_row, (Next_char_Col - 1)];
                }
                else if (Prev_char_Col == Next_char_Col)
                {
                    if (prev_char_row == 0)
                        prev_char_row = 5;
                    if (Next_char_row == 0)
                        Next_char_row = 5;
                    returnedText += Matrix[(prev_char_row - 1), Prev_char_Col];
                    returnedText += Matrix[(Next_char_row - 1), Next_char_Col];
                }
                else
                {
                    returnedText += Matrix[prev_char_row, Next_char_Col];
                    returnedText += Matrix[Next_char_row, Prev_char_Col];
                }

            }
            string plainText = "";
            plainText+=returnedText[0];
            for (int i = 1; i < returnedText.Length-1; i++)
            {
                if (returnedText[i-1]==returnedText[i+1]&& i % 2 != 0 &&returnedText[i]=='x')
                    continue;
                else
                    plainText += returnedText[i];              
            }
            if (returnedText.Last() != 'x')
                plainText += returnedText.Last();
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            //convert all char to Lowercase
            plainText = plainText.ToLower();

            // duplicate char --> add "x" between them 
            for (int i = 0; i < plainText.Length - 1; i += 2)
            {
                if (plainText[i] == plainText[i + 1])
                {
                    plainText = plainText.Insert(i + 1, "x");
                }
            }
            // Length is odd --> add "x"
            if (plainText.Length % 2 != 0)
                plainText += 'x';
            //Create Key Matrix
            char[,] Matrix = new char[5,5];
            Matrix = CreateMatrix(key);
            //Start Increipt
            int prev_char_row = 0, Prev_char_Col = 0 , Next_char_row = 0, Next_char_Col = 0 ;
            string Cipher = "";
            for (int i = 0; i < plainText.Length - 1; i += 2)
            {
                //get the indexs of each char
                for (int RowIndex = 0; RowIndex < 5; RowIndex++)
                {
                    for (int ColomeIndex = 0; ColomeIndex < 5; ColomeIndex++)
                    {
                        if (plainText[i] == Matrix[RowIndex, ColomeIndex])
                        {
                            prev_char_row = RowIndex;
                            Prev_char_Col = ColomeIndex;
                        }
                        if (plainText[i + 1] == Matrix[RowIndex, ColomeIndex])
                        {
                            Next_char_row = RowIndex;
                            Next_char_Col = ColomeIndex;
                        }


                    }

                }
                //start incript 
                if (prev_char_row == Next_char_row)
                {
                    Cipher += Matrix[prev_char_row, (Prev_char_Col + 1) % 5];
                    Cipher += Matrix[Next_char_row, (Next_char_Col + 1) % 5];
                }
                else if (Prev_char_Col == Next_char_Col)
                {
                    Cipher += Matrix[(prev_char_row + 1) % 5, Prev_char_Col];
                    Cipher += Matrix[(Next_char_row + 1) % 5, Next_char_Col];
                }
                else
                {
                    Cipher += Matrix[prev_char_row, Next_char_Col];
                    Cipher += Matrix[Next_char_row, Prev_char_Col];
                }

            }
            return Cipher;


        }
        public char[,] CreateMatrix(string key)
        {
            // store alphaptic 
            Dictionary<char, bool> dictionary = new Dictionary<char, bool>();
            for (char c = 'a'; c <= 'z'; c++)
            {
                dictionary.Add(c, true);
            }
            char[,] Matrix = new char[5, 5];
            int LastRow = 0;
            int LastColum = 0;
            //Fill Matrix with plainText
            for (int i = 0; i < key.Length; i++)
            {
                if (dictionary[key[i]] == true)
                {
                    Matrix[LastRow, LastColum] = key[i];
                    dictionary[key[i]] = false;
                    if (key[i] == 'i' || key[i] == 'j')
                    {
                        dictionary['i'] = false;
                        dictionary['j'] = false;
                    }
                    LastColum = (LastColum + 1) % 5;
                    if (LastColum == 0)
                        LastRow++;
                }
            }
            if (LastRow <= 4)
            {
                bool IS_I = true;
                foreach (var entry in dictionary)
                {
                    if (!IS_I && (entry.Key == 'j' || entry.Key == 'i'))
                        continue;
                    if (entry.Value == true)
                    {

                        Matrix[LastRow, LastColum] = entry.Key;
                        if (entry.Key == 'i' || entry.Key == 'j')
                        {
                            IS_I = false;
                        }

                        LastColum = (LastColum + 1) % 5;

                        if (LastColum == 0)
                            LastRow++;
                    }
                }
            }
            return Matrix;


           
        }
    }
}

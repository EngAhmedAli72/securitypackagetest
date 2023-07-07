using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public String alphaBit = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        char[,] arr;
        public String str = "", Res = "";
        int AlphaBitLength;
        public AutokeyVigenere() {
            alphaBit = alphaBit.ToLower(); 
            AlphaBitLength = alphaBit.Length;
            arr = new char[AlphaBitLength, AlphaBitLength];
            for (int i = 0; i < AlphaBitLength; i++)
            {
                for (int j = 0; j < AlphaBitLength; j++)
                {
                    int AscCode = (i + j) % AlphaBitLength;
                    arr[i, j] = alphaBit[AscCode];
                }
            }
        }


        public string Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            int plainLength = plainText.Length;
            cipherText = cipherText.ToLower();

            for (int i = 0; i < plainLength; i++)
            {
                int from = plainText[i] - 97;

                for (int j = 0; j < AlphaBitLength; j++)
                {
                    if (arr[from, j].Equals(cipherText[i]))
                    {
                        str += alphaBit[j];
                    }
                    else
                    {
                        continue;
                    }
                }
            }

            int stringLength = str.Length;

            for (int i = 1; i < stringLength; i++)
            {
                if (!Encrypt(plainText, str.Substring(0, i)).Equals(cipherText))
                {
                    continue; 
                }
                else
                {
                    return str.Substring(0, i);
                }
            }

            return null;
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            Res = "";
            int cipherLength = cipherText.Length;
            for (int i = 0; i < cipherLength; i++)
            {
                int from = (key[i]) - 97;
                for (int j = 0; j < AlphaBitLength; j++)
                {
                    if (arr[from, j].Equals(cipherText[i]))
                    {
                        Res += alphaBit[j];
                        key += alphaBit[j];
                    }
                    else
                    {
                        continue;
                    }
                }
            }
            return Res;
        }

        public string Encrypt(string plainText, string key)
        {
            Res = "";
            plainText = plainText.ToLower();
            int plainLength = plainText.Length;
            key += plainText;

            for (int i = 0; i < plainLength; i++)
            {
                Res += arr[plainText[i] - 97, key[i] - 97];
            }

            return Res;
        }
    }
}

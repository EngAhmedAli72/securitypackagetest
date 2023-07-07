using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public String alphaBit = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        char[,] arr;
        public String str = "", Res = "";
        int AlphaBitLength;

        public RepeatingkeyVigenere()
        {
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
            str = "";

            for (int i = 0; i < plainLength; i++)
            {
                int from = plainText[i] - 97;
                for (int j = 0; j < 26; j++)
                {
                    if (arr[from, j].Equals(cipherText[i]))
                    {
                        str += alphaBit[j];
                    }
                }
            }

            for (int i = 1; i < str.Length; i++)
            {
                if (Encrypt(plainText, str.Substring(0, i)).Equals(cipherText))
                {
                    return str.Substring(0, i);
                }
            }
            return null;
        }

        public string Decrypt(string cipherText, string key)
        {
            Res = "";

            int Counter = 0, cipherLength = cipherText.Length;
            while (true)
            {
                if (cipherLength > key.Length)
                {
                    key += key[Counter++];
                    Counter %= key.Length;
                }
                else
                {
                    break;
                }
            }
            int keyLength = key.Length;
            cipherText = cipherText.ToLower();
            for (int i = 0; i < keyLength; i++)
            {
                int from = (key[i]) - 97;
                for (int j = 0; j < AlphaBitLength; j++)
                {
                    if (!arr[from, j].Equals(cipherText[i]))
                    {
                        continue;
                    }
                    else
                    {
                        Res += alphaBit[j];
                    }
                }
            }
            return Res;
        }

        public string Encrypt(string plainText, string key)
        {
            int Counter = 0;
            Res = "";
            int plainLength = plainText.Length;

            while (true)
            {
                if (plainLength > key.Length)
                {
                    key += key[Counter++];
                    Counter %= key.Length;
                }
                else
                {
                    break;
                }
            }

            for (int i = 0; i < plainLength; i++)
            {
                Res += arr[plainText[i] - 97, key[i] - 97];
            }

            return Res;
        }
    }
}
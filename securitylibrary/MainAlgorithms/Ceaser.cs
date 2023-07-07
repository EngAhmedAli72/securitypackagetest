using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public const String acAlphabit = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        int idx ;
        public string Encrypt(string plainText, int key)
        {
            String Res = "";
            int length = plainText.Length  ;

            for (int i = 0; i < length; i++)
            {
                idx = acAlphabit.IndexOf(Char.ToUpper(plainText[i]));
                Res += acAlphabit[(idx + key) % acAlphabit.Length];
            }
            return Res;
        }

        public string Decrypt(string cipherText, int key)
        {
            String Res = "";
            int cipherLength = cipherText.Length;
            for (int i = 0; i < cipherLength ; i++)
            {
                idx = acAlphabit.IndexOf(Char.ToUpper(cipherText[i]));
                Res += acAlphabit[((idx - key) + acAlphabit.Length) % acAlphabit.Length];
            }
            return Res;
        }

        public int Analyse(string plainText, string cipherText)
        {
            int plainIdx = acAlphabit.IndexOf(char.ToUpper(plainText[0]));
            int ciperIdx = acAlphabit.IndexOf(char.ToUpper(cipherText[0]));

            if(plainIdx > ciperIdx)
                return  25 - ciperIdx;
            if (plainIdx <= ciperIdx)
                return Math.Abs(plainIdx - ciperIdx);
            else
                return 0;
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public const String acAlphabit = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        public int AlphabitLength = acAlphabit.Length;
        public String Res = "";
        public string Analyse(string plainText, string cipherText)
        {
            char[] arr = new char[AlphabitLength];
            int plainLength = plainText.Length, idx;
            string Str = "";

            for (int i = 0; i < plainLength; i++)
            {
                idx = acAlphabit.IndexOf(Char.ToUpper(plainText[i]));
                arr[idx] = cipherText[i];
            }

            for (int i = 0; i < AlphabitLength; i++)
            {
                if (cipherText.IndexOf(acAlphabit[i]) == -1)
                {
                    Str += Char.ToLower(acAlphabit[i]);
                }
                else
                    continue;
            }

            
            int StrIdx = 0;
            for (int i = 0; i < 26; i++)
            {
                if (arr[i] == '\0' || arr[i] == ' ')
                {
                    Res += Str[StrIdx++];
                }
                else
                {
                    Res += Char.ToLower(arr[i]);
                }
                if (i == 25)
                    return Res;
            }
            return Res;

        }

        public string Decrypt(string cipherText, string key)
        {
            int cipherLength = cipherText.Length;
            for (int i = 0; i < cipherLength; i++)
            {
                int ciperIndex = key.IndexOf(Char.ToLower(cipherText[i]));
                Res += acAlphabit[ciperIndex];
            }
            return Res;
        }

        public string Encrypt(string plainText, string key)
        {
            int PlainLength = plainText.Length;
            for (int i = 0; i < PlainLength; i++)
            {
                int plainIndex = acAlphabit.IndexOf(Char.ToUpper(plainText[i]));
                Res += key[plainIndex];
            }
            return Res;
        }
        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        string Frequency = "ETAOINSRHLDCUMFPGWYBVKXJQZ";
        Dictionary<char, int> lettersNumber = new Dictionary<char, int>();
        Dictionary<char,char> keyValuePairs = new Dictionary<char,char>();
        int index = 0;
        string plainText;
        public string AnalyseUsingCharFrequency(string cipher)
        {
            cipher = cipher.ToUpper();
            for(int i =0; i < AlphabitLength; i++)
            {
                lettersNumber[acAlphabit[i]]=0;
            }
            for(int i = 0; i < cipher.Length; i++)
            {
                lettersNumber[cipher[i]]+=1;
            }
            var sorted = lettersNumber.OrderByDescending(key => key.Value);
            foreach (var key in sorted)
            {
                keyValuePairs[key.Key] = Frequency[index];
                index++;
            }
            for(int i= 0; i < cipher.Length; i++)
            {
                plainText += keyValuePairs[cipher[i]];
            }
            return plainText;
            //throw new NotImplementedException();
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            int res = 0;
            int counter = 0;
            while(true) {             
                String cip = Encrypt(plainText, counter).ToLower();
                cipherText = cipherText.ToLower();

                if (cip == cipherText || counter == 100)
                {
                    res = counter;
                    break; 
                }
                else
                {

                   counter++;
                     continue;
                }
            }
            return res;
        }
        
        public char[,] arr;

        public string Decrypt(string cipherText, int key)
        {
            Encrypt(cipherText, key);

            int x = 0 , cipherLength = cipherText.Length;
            string Res = "";

            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < cipherLength; j++)
                {
                    if (arr[i, j] != '\0')
                    {
                        if(x < cipherLength)
                        {
                            arr[i, j] = cipherText[x++];
                        }
                        else
                        {
                            arr[i, j] = '\0';
                            continue;
                        }
                    }
                    else
                    {
                        arr[i, j] = '\0';
                        continue;
                    }
                }
            }

            for (int i = 0; i < cipherLength; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    if (arr[j, i] != '\0')
                    {
                        Res += arr[j, i];
                        continue;
                    }
                    else
                    {
                        break;
                    }
                }
            }

            return Res;
        }

        public string Encrypt(string plainText, int key)
        {
            int plainLength = plainText.Length, x = 0;
            arr = new char[key, plainLength];
            String Res = "";

            for (int i = 0; i < plainLength; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    if (x != plainLength)
                    {
                        arr[j, i] = plainText[x++];
                        continue;
                    }
                    else
                    {
                        break;
                    }
                }
            }

            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < plainLength; j++)
                {
                    if (arr[i, j] == '\0' || arr[i, j] == ' ')
                    {
                        continue;
                    }
                    else
                    {
                        Res += arr[i, j];
                    }
                }
            }
            return Res;
        }
    }
}

using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {

        static IEnumerable<IEnumerable<T>>
         GetPermutations<T>(int L, IEnumerable<T> Arr)
        {
            if (L == 1) { return Arr.Select(t => new T[] { t }); }
            else
            {
                return GetPermutations(L - 1, Arr)
                    .SelectMany(t => Arr.Where(e => !t.Contains(e)),
                        (t1, t2) => t1.Concat(new T[] { t2 }));
            }
            return GetPermutations(L - 1, Arr)
                    .SelectMany(t => Arr.Where(e => !t.Contains(e)),
                        (t1, t2) => t1.Concat(new T[] { t2 }));
        }



        public const String acAlphabit = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        //List<int> key = new List<int>();
        public List<int> Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToUpper();
            cipherText = cipherText.ToUpper();
            for (int i = 1; i < 11; i++)
            {
               List<List<int>> list = new List<List<int>>();
                List<IEnumerable<int>> Keys = new List<IEnumerable<int>>();
                int end = Fact(i);
                HashSet<int> Key = new HashSet<int>();
              
                IEnumerable<IEnumerable<int>> result =
                    GetPermutations( i,Enumerable.Range(1, i));
                Keys = result.ToList();
                foreach(var key in Keys)
                {
                    list.Add(key.ToList());
                }
                Console.WriteLine(result.Count());
                for(int j = 0; j < Keys.Count; j++)
                {
                    
                    string CT = Encrypt(plainText, list[j]);
                    CT = CT.Replace("\0", String.Empty);
                    CT.ToUpper();
                    if (CT == cipherText)
                    {
                        return list[j] ;
                    }

                }
            }
            //return Key;
            return null;
            //throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            bool exist = false;
            string Res = "";
            int chiperLength = cipherText.Length, keyLength = key.Count, x = 0, tmp = 0;

            int Divied = chiperLength / keyLength;

            if (chiperLength % keyLength != 0)
            {
                tmp = (chiperLength / keyLength) + 1;
                exist = true;
            }
            else
            {
                tmp = chiperLength / keyLength;
            }

            char[,] myarr = new char[tmp, keyLength];
            int[] arr = new int[keyLength];
            int arrLength = 0;

            for (int i = 0; i < keyLength; i++)
            {
                arr[i] = key.IndexOf(i + 1);
                arrLength++;
            }

            for (int i = 0; i < arrLength; i++)
            {
                for (int j = 0; (j < tmp) && (x < chiperLength); j++)
                {
                    if ((j == (tmp - 1)) && (i > Divied))
                    {
                        if (exist)
                        {
                            myarr[j, arr[i]] = '\0';
                        }
                        else
                        {
                            myarr[j, arr[i]] = cipherText[x];
                            x++;
                        }
                    }
                    else
                    {
                        myarr[j, arr[i]] = cipherText[x];
                        x++;
                    }
                }
            }

            for (int i = 0; i < tmp; i++)
            {
                for (int j = 0; j < keyLength; j++)
                {
                    if (myarr[i, j] != '\0' || myarr[i, j] != ' ')
                    {
                        Res += myarr[i, j];
                    }
                    else
                    {
                        continue;
                    }
                }
            }
            //throw new NotImplementedException();

            return Res;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            int maxIdx = 0, x = 0;
            int plainLength = plainText.Length, keyLength = key.Count;
            string Res = "";

            char[,] arr = new char[keyLength, keyLength];
    
            // fill array
            for (int i = 0; i < keyLength; i++)
            {
                for (int j = 0; ((j < keyLength) && (x < plainLength)); j++)
                {
                    arr[i, j] = plainText[x];
                    x++;
                }
            }

            // read result 
            for (int i = 0; i < keyLength; i++)
            {
                int nextIdx =0;
                for (int k = 0; k < keyLength; k++)
                {
                    if (key[k] == i + 1)
                    {
                        nextIdx = k;
                    }
                    else
                    {
                        continue;
                    }
                }

                for (int j = 0; j < keyLength; j++)
                {
                    if (arr[j, nextIdx] != '\0' || arr[j, nextIdx] != ' ')
                    {
                        Res += arr[j, nextIdx];
                    }
                    else
                    {
                        break;
                    }
                }
            }

            return Res;
        }
        int Fact(int number)
        {
            int fact = 1;
            for (int i = 1; i <= number; i++)
            {
                fact = fact * i;
            }
            return fact;
        }
    }
}

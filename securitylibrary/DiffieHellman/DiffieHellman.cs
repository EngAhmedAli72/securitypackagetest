using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
    {
        public int Pow(int baseA, int power, int N)
        {
            int res = 1;
            for (int i = 0; i < power; i++)
            {
                res = (res * baseA) % N;
            }
            return res;
        }
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            //throw new NotImplementedException();
           List<int> result = new List<int>();
           //key Generation 
           int yA = Pow(alpha, xa, q);
           int yB = Pow(alpha, xb, q);
           // calc secrit key
           int kA = Pow(yB, xa, q);
           int kb = Pow(yA, xb, q);
           result.Add(kA);
           result.Add(kb);
           return result;


        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        /// 

        void Replace(ref int a, ref int b, int NewA, int NewB, int mod )
        {
      
            a = NewA % mod;
            b = NewB % mod;
        }
        public int InverseMod(int Value, int mod)
        {
            int a = Value;
            int b = mod;
            int x = 1;
            int y = 0;
            int x1 = 0;
            int y1 = 1;
            int q;
            while (b != 0)
            {
                q = a / b;
                Replace(ref y, ref y1, y1, y - q * y1, mod);
                Replace(ref x, ref x1, x1, x - q * x1, mod);
                Replace(ref a, ref b, b, a - q * b, 1000000000);
            }
            return (x % mod + mod) % mod;
        }
        public int Power(int Base, int power, int mod)
        {
            int result = 1;

            for (int i = 0; i < power; i++)
            {
                if (mod == 1)
                {
                    result = 0;
                    return result;
                }

                int tmp = (result * Base);
                result = tmp % mod;
            }
            return result;
        }

        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            long C1, C2, K;
            C1 = Power(alpha, k, q);  // public Key 
            K = Power(y, k, q);  // provate Key 
            C2 = K * m % q; // y Ciphar

            return new List<long>() { C1, C2 };
        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            return c2 * InverseMod(Power(c1, x, q), q) % q;
        }
    }
}

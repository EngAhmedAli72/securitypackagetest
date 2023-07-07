using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Pow(int baseA ,int power , int N)
        {
            int res = 1;
            for (int i = 0; i < power; i++)
            {
                res = (res * baseA) % N;
            }
            return res;
        }

        public int Encrypt(int p, int q, int M, int e)
        {
            // throw new NotImplementedException();

            int N = p * q;
            int Q_N = (p - 1) * (q - 1);
            int res = Pow(M, e, N);
            // int res = (Convert.ToInt32(Math.Pow(M, e) % N)) % N;
            return res;


        }

        public int Decrypt(int p, int q, int C, int e)
        {
           // throw new NotImplementedException();

            //int d = (Convert.ToInt32(Math.Pow(e, -1)) % Q_N) % Q_N;
            //int res = (Convert.ToInt32(Math.Pow(C, d) % N)) % N;

            int N = p * q;
            int Q_N = (p - 1) * (q - 1);

            //calc d
            int temp1, temp2, temp3 ;
            int a1 = 1;
            int a2 = 0;
            int a3 = Q_N;
            int b1 = 0;
            int b2 = 1;
            int b3 = e;
            int Q = 0;
            int d = -1;
            while(b3>=1)
            {
                if (b3 == 1)
                {
                    if (b2 < 1)
                        b2 += Q_N;
                    d = b2;
                }
            
                temp1 = a1;
                temp2 = a2;
                temp3 = a3;

                Q = a3 / b3;
                a1 = b1;
                a2 = b2;
                a3 = b3;

                b1 = temp1 - b1 * Q;
                b2 = temp2 - b2 * Q;
                b3 = temp3 % b3;

            }
            return Pow(C, d, N);




        }
    }
}

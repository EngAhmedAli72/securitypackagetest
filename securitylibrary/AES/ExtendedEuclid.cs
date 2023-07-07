using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid 
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            int copyBaseN = baseN, comyNuber = number, sum = 0 , multblication = 1 ,temp ,result ;            
            while(true)
            {
                if (comyNuber == 0)
                    break;
                else
                {
                    result = copyBaseN / comyNuber;
                    temp = copyBaseN - result * comyNuber;
                    copyBaseN = comyNuber;
                    comyNuber = temp;
                    temp = sum - result * multblication;
                    sum = multblication;
                    multblication = temp;
                }
            }
            if (sum < 0)
                sum = sum + baseN;
            if (copyBaseN > 1)
                return -1;
            else
                return sum;

        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<List<int>, List<int>>
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
        List<int> Key;
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            //int[,] ma = GetKeyMatrix(plainText, 2);
            //try
            //{
            //    InversMatrix2X2(ma, 2);
            //    //return list[j];
            //}
            //catch (Exception)
            //{

            //    throw new InvalidAnlysisException();
            //}
            List<List<int>> list = new List<List<int>>();
            List<IEnumerable<int>> Keys = new List<IEnumerable<int>>();
            IEnumerable<IEnumerable<int>> result =
                    GetPermutations(4, Enumerable.Range(0, 25));
            Keys = result.ToList();
            foreach (var key in Keys)
            {
                list.Add(key.ToList());
            }
            bool equals = true;
            int index ;
            for (int j = 0; j < list.Count; j++)
            {
                equals = true;
                List<int> CT = Encrypt(plainText, list[j]);
                for(int i = 0; i < CT.Count; i++)
                {
                    if(CT[i] != cipherText[i])
                    {
                        equals = false;
                        break;
                    }
                }
                if (equals)
                {
                    return list[j];
                }


            }
            if (!equals)
            {
                throw new InvalidAnlysisException();
            }
            return Key; 
            //throw new NotImplementedException();
        }
        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            //Create Key Matrix
            int M = (int)Math.Sqrt(key.Count());
            int[,] InverseKeyMatrix = new int[M, M];
            int ColSize = (cipherText.Count / M);
            int[,] KeyMatrix = GetKeyMatrix(key, M);
            //Create CipherTextMatrix 
            int[,] CipherTextMatrix = GetPlainTextMatrix(cipherText, M);
            if (M == 2)
                InverseKeyMatrix = InversMatrix2X2(KeyMatrix, M);
            else
                InverseKeyMatrix = InverseMatrix3X3(KeyMatrix, M);
            // start incript  
            int[,] CipheredMatrix = new int[M, ColSize];
            for (int M1R = 0; M1R < M; M1R++)
            {
                for (int M2C = 0; M2C < ColSize; M2C++)
                {
                    CipheredMatrix[M1R, M2C] = 0;
                    for (int j = 0; j < M; j++)
                        CipheredMatrix[M1R, M2C] += (InverseKeyMatrix[M1R, j] * CipherTextMatrix[j, M2C]);
                    CipheredMatrix[M1R, M2C] = ((CipheredMatrix[M1R, M2C] % 26) + 26) % 26;    //%26    
                }
            }
            List<int> PlainText = new List<int>();
            for (int Col = 0; Col < ColSize; Col++)
            {
                for (int Row = 0; Row < M; Row++)
                {
                    PlainText.Add(CipheredMatrix[Row, Col]);
                }
            }
            return PlainText;
        }
        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            //Create Key Matrix
            int M = (int)Math.Sqrt(key.Count());
            int i = 0;
            int[,] KeyMatrix = new int[M, M];
            KeyMatrix = GetKeyMatrix(key, M);
            int[,] PlainTextMatrix = GetPlainTextMatrix(plainText, M);
            int ColSize = (plainText.Count / M);
            // start incript  
            int[,] CipheredMatrix = new int[M, ColSize];
            for (int M1R = 0; M1R < M; M1R++)
            {
                for (int M2C = 0; M2C < ColSize; M2C++)
                {
                    CipheredMatrix[M1R, M2C] = 0;
                    for (int j = 0; j < M; j++)
                        CipheredMatrix[M1R, M2C] += (KeyMatrix[M1R, j] * PlainTextMatrix[j, M2C]);
                    CipheredMatrix[M1R, M2C] %= 26;
                }

            }
            List<int> Cipher = new List<int>();
            for (int Col = 0; Col < ColSize; Col++)
            {
                for (int Row = 0; Row < M; Row++)
                {
                    Cipher.Add(CipheredMatrix[Row, Col]);
                }
            }
            return Cipher;
        }
        public static int[,] InversMatrix2X2(int[,] Matrix, int M)
        {
            int[,] inverseMatrix = new int[2, 2];
            inverseMatrix = Matrix;
            int det = (inverseMatrix[0, 0] * inverseMatrix[1, 1]) - (inverseMatrix[0, 1] * inverseMatrix[1, 0]);
            det = ((det % 26) + 26) % 26;    //%26    
            int B = GetB(det);
            swap(ref inverseMatrix[0, 0], ref inverseMatrix[1, 1]);
            inverseMatrix[0, 1] = inverseMatrix[0, 1] * -1;
            inverseMatrix[1, 0] = inverseMatrix[1, 0] * -1;
            for (int i = 0; i < 2; i++)
            {
                for (int j = 0; j < 2; j++)
                {
                    inverseMatrix[i, j] = B * (inverseMatrix[i, j]);
                    Console.Write(inverseMatrix[i, j] + " ");
                }
                Console.WriteLine();
            }
            return inverseMatrix;
        }
        public int[,] InverseMatrix3X3(int[,] Matrix, int M)
        {
            // throw new NotImplementedException();
            int det = 0, subDet = 0;
            int[,] Adj = new int[3, 3];
            int[,] MatrixT = new int[3, 3];
            int[,] InverseMatrix = new int[3, 3];
            for (int i = 0; i < 3; i++)
            {
                det += (Matrix[0, i] * (Matrix[1, (i + 1) % 3] * Matrix[2, (i + 2) % 3] - Matrix[1, (i + 2) % 3] * Matrix[2, (i + 1) % 3]));
            }
            det = ((det % 26) + 26) % 26;    //%26    
            int B = GetB(det);
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    MatrixT[j, i] = Matrix[i, j];
                }
            }
            Matrix = MatrixT;
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    subDet = Matrix[(i + 1) % 3, (j + 1) % 3] * Matrix[(i + 2) % 3, (j + 2) % 3]
                        - Matrix[(i + 1) % 3, (j + 2) % 3] * Matrix[(i + 2) % 3, (j + 1) % 3];
                    Adj[i, j] = subDet;
                    InverseMatrix[i, j] = Adj[i, j] * B;
                }
            }

            return InverseMatrix;
        }
        public static void swap(ref int xp, ref int yp)
        {
            int temp = xp;
            xp = yp;
            yp = temp;
        }
        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            //   throw new NotImplementedException();
            int M = (int)Math.Sqrt(plainText.Count());
            int ColSize = (cipherText.Count / M);
            int[,] PlainTextMatrix = GetKeyMatrix(plainText, M);
            int[,] cipherTextMatrix = GetKeyMatrix(cipherText, M);
            int[,] InversePlainTextMatrix = new int[M, M];
            InversePlainTextMatrix = InverseMatrix3X3(PlainTextMatrix, M);

            // start Getting The Key
            int[,] KeyTextMatrix = new int[M, ColSize];
            for (int M1R = 0; M1R < M; M1R++)
            {
                for (int M2C = 0; M2C < ColSize; M2C++)
                {
                    KeyTextMatrix[M1R, M2C] = 0;
                    for (int j = 0; j < M; j++)
                        KeyTextMatrix[M1R, M2C] += (InversePlainTextMatrix[M1R, j] * cipherTextMatrix[j, M2C]);
                    KeyTextMatrix[M1R, M2C] = ((KeyTextMatrix[M1R, M2C] % 26) + 26) % 26;    //%26    
                }

            }

            List<int> KeyText = new List<int>();
            for (int Col = 0; Col < ColSize; Col++)
            {
                for (int Row = 0; Row < M; Row++)
                {
                    KeyText.Add(KeyTextMatrix[Row, Col]);
                }

            }
            return KeyText;
        }
        public static int GetB(int det)
        {
            int C_cofactor = 26 - det;
            int C = 1;
            if (GCD(26, det) != 1)
                throw new InvalidAnlysisException();
            while (true)
            {
                if ((C * C_cofactor) % 26 == 1)
                    return 26 - C;
                else
                    C++;
            }
        }
        static int GCD(int num1, int num2)
        {
            int Remainder;

            while (num2 != 0)
            {
                Remainder = num1 % num2;
                num1 = num2;
                num2 = Remainder;
            }

            return num1;
        }
        public int[,] GetPlainTextMatrix(List<int> plainText, int M)
        {

            int i = 0;
            int ColSize = (plainText.Count / M);
            int[,] PlainTextMatrix = new int[M, ColSize];
            //Create PlainText Matrix
            for (int ColmIndex = 0; ColmIndex < ColSize; ColmIndex++)
            {

                for (int RowIndex = 0; RowIndex < M; RowIndex++)
                {
                    PlainTextMatrix[RowIndex, ColmIndex] = plainText.ElementAt(i);
                    i++;
                }
            }
            return PlainTextMatrix;
        }
        public int[,] GetKeyMatrix(List<int> key, int M)
        {
            M = (int)Math.Sqrt(key.Count());
            int[,] KeyMatrix = new int[M, M];
            int i = 0;
            //Create Key Matrix
            for (int RowIndex = 0; RowIndex < M; RowIndex++)
            {
                for (int ColmIndex = 0; ColmIndex < M; ColmIndex++)
                {
                    KeyMatrix[RowIndex, ColmIndex] = key.ElementAt(i);
                    i++;
                }
            }
            return KeyMatrix;
        }


    }


}


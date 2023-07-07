using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

//using System.Security.Cryptography;
//using System.Diagnostics;


namespace SecurityLibrary.MD5
{
    public class MD5
    {

        //CLS
        //R1 = 7 12 17 22, 
        //R2 = 5 9 14 20
        //R3 = 4 11 16 23, 
        //R4 = 6 10 15 21

        static int[] AmountOfShift = new int[] {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, //first 16
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,   //sac 16
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, //thirs 16
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21 //fourst 16
    };


        public static uint CalculateT(uint i)
        {
            double sin = Math.Abs(Math.Sin(i));
            return (uint)(Math.Pow(2, 32) * sin);
        }

        public static uint LeftRotate(uint x, int ShiftNumber)
        {
            return (x << ShiftNumber) | (x >> (32 - ShiftNumber));
        }

        //converts the byte array to a hexadecimal string
        //representation using a StringBuilder and the ToString("x2") method to format each byte as a two-digit hexadecimal number.
        public StringBuilder ConvertToHex(byte[] HashCode)
        {
            StringBuilder str = new StringBuilder();

            //convert Each byte to Hex
            foreach (byte i in HashCode)
            {
                str.AppendFormat("{0:x2}", i);
                //str.Append(i.ToString("x2"));
            }

            return str;
        }

        public string GetHash(string text)
        {
            //System.Security.Cryptography.MD5 MD5_Object = new MD5CryptoServiceProvider();
            //byte[] MyHashCode = MD5_Object.ComputeHash(Encoding.ASCII.GetBytes(text));
            //return ConvertToHex(MyHashCode).ToString();

            //converts text to a byte array using the UTF-8 encoding
            //compute the MD5 hash of the byte array
            byte[] MyHashCode = CalcMD5HashCode(Encoding.UTF8.GetBytes(text));

            return ConvertToHex(MyHashCode).ToString();

        }

        public static byte[] CalcMD5HashCode(byte[] text)
        {
            int inputLength, LengthOfPadding, paddedLength;
            byte[] hashCode = new byte[16];

            inputLength = text.Length;

            //Step 1 – append padded bits
            //computes number of padding bits needed to ensure that the input is a multiple of 512 bits
            //The message is padded so that its length is congruent to 448, modulo 512.
            LengthOfPadding = (448 - inputLength * 8 % 512) % 512;

            //Step 2 – append length
            paddedLength = inputLength + (LengthOfPadding / 8) + 8;

            //creates a array of padded length and copies the input byte array into it.
            byte[] paddedInput = new byte[paddedLength];
            Array.Copy(text, paddedInput, inputLength);

            //Step 3 – initializes a 128-bit MD Buffer of intermediate hash values A,B,C,D
            uint[] buffer = new uint[4] { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };

            //padding bit of the padded input byte array to 1
            //appends the length of the input in bits as a 64-bit integer in end of the padded input.
            paddedInput[inputLength] = 0x80;
            byte[] bitLength = BitConverter.GetBytes((ulong)inputLength * 8);
            Array.Copy(bitLength, 0, paddedInput, paddedLength - 8, 8);

            //calculate Const T
            uint[] T = new uint[64];

            for (int i = 0; i < 64; i++)
            {
                T[i] = (uint)(Math.Floor(Math.Pow(2, 32) * Math.Abs(Math.Sin(i + 1))));
            }

            // Step 4 – Process message in 16-word blocks
            // processes the padded input byte array in 512-bit blocks
            for (int i = 0; i < paddedLength; i += 64)
            {
                uint[] block = new uint[16];
                for (int j = 0; j < 16; j++)
                {
                    int index = i + j * 4;
                    block[j] = (uint)paddedInput[index] |
                        ((uint)paddedInput[index + 1] << 8) |
                        ((uint)paddedInput[index + 2] << 16) |
                        ((uint)paddedInput[index + 3] << 24);
                }
                uint a = buffer[0], b = buffer[1], c = buffer[2], d = buffer[3];
                uint f, g;

                for (uint j = 0; j < 64; j++)
                {
                    uint tmp = d;

                    if (j < 16)
                    {
                        f = (b & c) | (~b & d);
                        g = j;
                    }
                    else if (j < 32)
                    {
                        f = (d & b) | (~d & c);
                        g = (5 * j + 1) % 16;
                    }
                    else if (j < 48)
                    {
                        f = b ^ c ^ d;
                        g = (3 * j + 5) % 16;
                    }
                    else if (j < 64)
                    {
                        f = c ^ (b | ~d);
                        g = (7 * j) % 16;
                    }
                    else
                    {
                        break;
                    }

                    d = c;
                    c = b;
                    b += LeftRotate(a + f + block[g] + T[j], AmountOfShift[j]);
                    a = tmp;
                }

                // updating the buffer of intermediate hash values at each step.
                buffer[0] += a;
                buffer[1] += b;
                buffer[2] += c;
                buffer[3] += d;
            }

            //converts the values in the buffer of intermediate hash values to a byte array of length 16, which represents the MD5 hash of the input
            for (int i = 0; i < 4; i++)
            {
                byte[] tmp = BitConverter.GetBytes(buffer[i]);
                Array.Copy(tmp, 0, hashCode, i * 4, 4);
            }
            return hashCode;
        }

    }
}
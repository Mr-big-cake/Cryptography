using System;
using System.Numerics;

namespace Coursework_Cryptography
{
    public class Program
    {
        static void Main(string[] args)
        {

            var b = new byte[] { 11, 12, 47, 11, 12, 47, 0, 88, 11, 12, 47, 11, 12, 47, 0, 88 };
            var text = LUC.Encrypt(b);
            var chiper = LUC.Decrypt(text);
            Console.WriteLine("Текст: " + new BigInteger(b) + "\nЗашифрованый текст: " +  new BigInteger (text) + "\n\n");
            for(int i = 0; i< 50000; i++)
                if(new BigInteger(b) != new BigInteger(chiper))
                 Console.WriteLine(new BigInteger(chiper));
        }
    }
}

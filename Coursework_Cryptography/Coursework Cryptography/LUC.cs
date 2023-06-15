using System;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
namespace Coursework_Cryptography
{
    public static class LUC
    {
        #region Вспомогательные функции 
        public static BigInteger GetPrime(int size)
        {
            Random rnd = new Random();
            byte[] arr = new byte[size];
            rnd.NextBytes(arr);
            arr[size - 1] &= 0b01111111;
            BigInteger res = new BigInteger(arr);
            while (!MillerRabin(res, 30))
            {
                res++;
                if (res.ToByteArray().Length > size)
                {
                    rnd.NextBytes(arr);
                    arr[size - 1] &= 0b01111111;
                    res = new BigInteger(arr);
                }
            }

            return res;
        }

        public static bool MillerRabin(BigInteger n, int k) // n - проверяемое на простоту число, k - количество раундов
        {
            if (n == 2 || n == 3) return true; //проверку проходит нечетное число > 3
            if (n < 2 || n % 2 == 0) return false;
            BigInteger t = n - 1;
            int s = 0;
            while (t % 2 == 0) //для представления числа (n - 1) в виде (2^s * t)
            {
                t /= 2;
                s += 1;
            }

            for (int i = 0; i < k; i++) // проверка осуществляется k раз (раундов)
            {
                RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider(); //более криптоустойчивый поиск псевдослучайного числа (более "случайного" и более длинного)
                byte[] _a = new byte[n.ToByteArray().LongLength]; //создали массив длинной количества байт n
                BigInteger a;
                do
                {
                    rng.GetBytes(_a);
                    a = new BigInteger(_a);
                }
                while (a < 2 || a >= n - 2); // пока a не лежит на отрезке (2 > a >= n - 2) генерируем его заново

                BigInteger x = ModPow(a, t, n); // быстрое возведение в степень по модулю (x = a^t mod n)
                if (x == 1 || x == n - 1) continue; // тест пройден, переход в следующий раунд
                for (int r = 1; r < s; r++) // цикл повторяется (s - 1) раз
                {
                    x = ModPow(x, 2, n);
                    if (x == 1) return false; // число составное
                    if (x == n - 1) break; // тест пройден, переход в следующий раунд
                }

                if (x != n - 1) return false; // число составное
            }

            return true;
        }

        public static BigInteger ModPow(BigInteger a, BigInteger n, BigInteger mod) // быстрое возведение в степень по модулю
        {
            if (a < 0) a = a + (mod - 1);
            BigInteger res = 1;
            a = a % mod;
            while (n > 0)
            {
                if ((n & 1) == 1)
                {
                    res *= a;
                    res %= mod;
                }

                a *= a;
                a %= mod;
                n >>= 1;
            }

            return res;
        }

        public static BigInteger GCD(BigInteger a, BigInteger b)
        {
            BigInteger c;
            while (b != 0)
            {
                a %= b;
                c = a;
                a = b;
                b = c;
            }

            return a;
        }

        public static BigInteger LCM(BigInteger a, BigInteger b)
        {
            return (a * b) / GCD(a, b);
        }

        public static int Legandre(BigInteger a, BigInteger p)
        {
            if (a == 0)
            {
                return 0;
            }
            if (a == 1)
            {
                return 1;
            }
            int result;
            if (a % 2 == 0)
            {
                result = Legandre(a / 2, p);
                if (((p * p - 1) & 8) != 0)
                {
                    result = -result;
                }
            }
            else
            {
                result = Legandre(p % a, a);
                if (((a - 1) * (p - 1) & 4) != 0)
                {
                    result = -result;
                }
            }
            return result;
        }

        public static BigInteger QuickPow(BigInteger a, BigInteger n)
        {
            BigInteger res = 1;
            while (!n.Equals(0))
            {
                if ((n & 1) == 1)
                    res *= a;
                a *= a;
                n >>= 1;
            }

            return res;
        }

        public static BigInteger ExtendedGCD(BigInteger a, BigInteger b, ref BigInteger x, ref BigInteger y)
        {
            if (a == 0)
            {
                x = 0;
                y = 1;
                return b;
            }

            BigInteger x1 = 0, y1 = 0;
            BigInteger d = ExtendedGCD(b % a, a, ref x1, ref y1);
            x = y1 - (b / a) * x1;
            y = x1;
            return d;
        }

        public static BigInteger ModIversion(BigInteger value, BigInteger modulo)
        {
            BigInteger left = 0, right = 0;
            var egcd = ExtendedGCD(value, modulo, ref left, ref right);
            if (left < 0) left += modulo;
            return left % modulo;
        }
        #endregion

        #region Поля и свойства класса
        private static BigInteger _p , _q, _N, _D, _PublicKey, _PrivateKey, _Dq, _Dp, _S;
        public static int _BlockSize;
        static LUC()
        {
            _BlockSize = 9;
            _p = GetPrime(_BlockSize);
            _q = GetPrime(_BlockSize);
            _N = _p * _q;
            CalcPublicKey();
        }
        //public static String GetOpenKeys()
        //{
        //    return _N + " " + _PublicKey;
        //}

        #endregion



        #region Вычисления: публичного и приватного ключей 
        public static void CalcPublicKey()
        {
            BigInteger a = (_p - 1) * (_p + 1) * (_q - 1) * (_q + 1);
            do
            {
                _PublicKey = GetPrime(_BlockSize);
            }
            while (GCD(a, _PublicKey) != 1);
        }

        private static void CalcPrivateKey()
        {
            _PrivateKey = ModIversion(_PublicKey, _S);
        }
        #endregion

        #region Шифрование и дешифрование


        public static byte[] Encrypt(byte[] data)
        {
            BigInteger message = new BigInteger(data);
            return CalculateVMod(_PublicKey, message, _N).ToByteArray();
        }
        public static byte[] Decrypt(byte[] data)
        {
            BigInteger message = new BigInteger(data);
            _D = message * message - 4;
            _Dp = Legandre(_D, _p);
            _Dq = Legandre(_D, _q);
            _S = LCM(_p - _Dp, _q - _Dq);
            CalcPrivateKey();
            return CalculateVMod(_PrivateKey, message, _N).ToByteArray();
        }

        private static BigInteger CalculateVMod(BigInteger n, BigInteger P, BigInteger mod)
        {
            var k = CalculateCountOfOperation(n);
            BigInteger prev = 2, current = P;
            var enumerator = k.GetEnumerator();

            for (int i = k.Count - 1; i >= 0; i--)
            {
                var currentIndex = k[i];
                if (currentIndex == 0)
                {
                    BigInteger V2tn = ((current * current) - 2);
                    BigInteger Vtn1 = ((current * prev) - P);
                    prev = Vtn1 % mod;
                    current = V2tn % mod;
                }
                else if (currentIndex == 1)
                {
                    BigInteger Vtn1 = (((P * (current * current)) - (current * prev)) - P);
                    prev = ((current * current) - 2) % mod;
                    current = Vtn1 % mod;
                }
                else
                {
                    break;
                }
            }

            return current;
        }

        private static List<int> CalculateCountOfOperation(BigInteger index)
        {
            List<int> array = new List<int>() { 2 };

            while (index > 1)
            {
                if ((index & 1) == 1)
                {
                    index--;
                    index >>= 1;
                    array.Add(1);
                }
                else
                {
                    index >>= 1;
                    array.Add(0);
                }
            }
            return array;
        }

        #endregion

    }
}

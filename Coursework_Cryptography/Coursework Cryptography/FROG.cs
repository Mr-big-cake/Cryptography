using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;

namespace Coursework_Cryptography
{
    public enum Order
    {
        Encrypt, Decrypt
    }

    public static class FROG
    {
        private static int SizePie;
        private static byte[] _key;
        public static byte[] Key { get => _key; set { _key = value; }  }
        private static byte[][][] RoundKeysEncrypt;
        private static byte[][][] RoundKeysDecrypt;

        private static byte[] MasterKey251 = new byte[]
        {
            113,  21, 232,  18, 113,  92,  63, 157, 124, 193, 166, 197, 126,  56, 229, 229,
            156, 162,  54,  17, 230,  89, 189,  87, 169,   0,  81, 204,   8,  70, 203, 225,
            160,  59, 167, 189, 100, 157,  84,  11,   7, 130,  29,  51,  32,  45, 135, 237,
            139,  33,  17, 221,  24,  50,  89,  74,  21, 205, 191, 242,  84,  53,   3, 230,
            231, 118,  15,  15, 107,   4,  21,  34,   3, 156,  57,  66,  93, 255, 191,   3,
             85, 135, 205, 200, 185, 204,  52,  37,  35,  24,  68, 185, 201,  10, 224, 234,
              7, 120, 201, 115, 216, 103,  57, 255,  93, 110,  42, 249,  68,  14,  29,  55,
            128,  84,  37, 152, 221, 137,  39,  11, 252,  50, 144,  35, 178, 190,  43, 162,
            103, 249, 109,   8, 235,  33, 158, 111, 252, 205, 169,  54,  10,  20, 221, 201,
            178, 224,  89, 184, 182,  65, 201,  10,  60,   6, 191, 174,  79,  98,  26, 160,
            252,  51,  63,  79,   6, 102, 123, 173,  49,   3, 110, 233,  90, 158, 228, 210,
            209, 237,  30,  95,  28, 179, 204, 220,  72, 163,  77, 166, 192,  98, 165,  25,
            145, 162,  91, 212,  41, 230, 110,   6, 107, 187, 127,  38,  82,  98,  30,  67,
            225,  80, 208, 134,  60, 250, 153,  87, 148,  60,  66, 165,  72,  29, 165,  82,
            211, 207,   0, 177, 206,  13,   6,  14,  92, 248,  60, 201, 132,  95,  35, 215,
            118, 177, 121, 180,  27,  83, 131,  26,  39,  46,  12
        };

        static FROG()
        {
            SizePie = 16;
            Random random = new Random();
            _key = new byte[SizePie];
            random.NextBytes(_key);
            
            RoundKeysEncrypt = GenerateKey(_key, Order.Encrypt);
            RoundKeysDecrypt = GenerateKey(_key, Order.Decrypt);
        }

        public static byte[] Encrypt(byte[] DataBytes)
        {
            byte[] bufResult = new byte[DataBytes.Length];
            DataBytes.CopyTo(bufResult, 0);

            for (int round = 0; round < 8; round++)
            {
                for (int i = 0; i < SizePie; i++)
                {
                    // 1
                    bufResult[i] ^= RoundKeysEncrypt[round][0][i];
                    // 2
                    bufResult[i] = RoundKeysEncrypt[round][1][bufResult[i]];
                    // 3
                    if (i < SizePie - 1)
                        bufResult[i + 1] ^= bufResult[i];
                    // 4
                    byte index = RoundKeysEncrypt[round][2][i];
                    bufResult[index] ^= bufResult[i];
                }
            }

            return bufResult;
        }

        private static byte[] EncryptCBC(byte[] inputBuffer, byte[] iv, byte[][][] encryptRoundKeys, int inputOffset, byte[] bufResult, int outputOffset)
        {
            Array.Copy(inputBuffer, inputOffset, bufResult, outputOffset, SizePie);

            for (int i = 0; i < SizePie; i++)
                bufResult[i] ^= iv[i];

            for (int round = 0; round < 8; round++)
            {
                for (int i = 0; i < SizePie; i++)
                {
                    // 1
                    bufResult[outputOffset + i] ^= encryptRoundKeys[round][0][i];
                    // 2
                    bufResult[outputOffset + i] = encryptRoundKeys[round][1][bufResult[outputOffset + i]];
                    // 3
                    if (i < SizePie - 1)
                        bufResult[outputOffset + i + 1] ^= bufResult[outputOffset + i];
                    // 4
                    byte index = encryptRoundKeys[round][2][i];
                    bufResult[outputOffset + index] ^= bufResult[outputOffset + i];
                }
            }

            return bufResult;
        }

        public static byte[] Decrypt(byte[] DataBytes)
        {
            byte[] bufResult = new byte[DataBytes.Length];
            DataBytes.CopyTo(bufResult, 0);

            for (int round = 7; round >= 0; round--)
            {
                for (int i = SizePie - 1; i >= 0; i--)
                {
                    // 4
                    byte index = RoundKeysDecrypt[round][2][i];
                    bufResult[index] ^= bufResult[i];
                    // 3
                    if (i < SizePie - 1)
                        bufResult[i + 1] ^= bufResult[i];
                    // 2
                    bufResult[i] = RoundKeysDecrypt[round][1][bufResult[i]];
                    // 1
                    bufResult[i] ^= RoundKeysDecrypt[round][0][i];
                }
            }

            return bufResult;
        }

        private static byte[][][] GenerateKey(byte[] key, Order Order)
        {
            // 1
            byte[] keyExpanded = Expand(key, 2304);
            // 2
            byte[] masterKeyExpanded = Expand(MasterKey251, 2304);
            // 3
            for (int i = 0; i < 2304; i++)
                keyExpanded[i] = (byte)(keyExpanded[i] ^ masterKeyExpanded[i]);
            // 4
            byte[][][] preliminaryKey = FormatExpandedKey(keyExpanded, Order.Encrypt);
            // 5
            byte[] iv = new byte[SizePie];
            Array.Copy(keyExpanded, iv, SizePie);
            iv[0] ^= (byte)key.Length;

            byte[] result = TransformEmptyText(preliminaryKey, iv);
            // 6
            return FormatExpandedKey(result, Order);
        }

        private static T[] Expand<T>(T[] array, int newLength)
        {
            T[] result = new T[newLength];
            for (int i = 0; i < newLength; i++)
                result[i] = array[i % array.Length];
            return result;
        }

        // Процедура форматирования ключа
        private static byte[][][] FormatExpandedKey(byte[] expandedKey, Order Order)
        {
            int bytesInKey = 288;// 16 + 256 + 16
            byte[][][] result = new byte[8][][];// indices: round, key(16, 256, 16), byteIndex
            for (int i = 0; i < 8; i++)
            {
                // 1
                byte[] key1 = new byte[16];
                byte[] key2 = new byte[256];
                byte[] key3 = new byte[16];

                Array.Copy(expandedKey, i * bytesInKey, key1, 0, 16);
                Array.Copy(expandedKey, i * bytesInKey + 16, key2, 0, 256);
                Array.Copy(expandedKey, i * bytesInKey + 272, key3, 0, 16);

                // 2
                Format(key2);
                if (Order == Order.Decrypt)
                    key2 = Invert(key2);

                // 3.a
                Format(key3);
                // 3.b
                MakeSingleCycle(key3);
                // 3.c
                for (int j = 0; j < 16; j++)
                    if (key3[j] == j + 1)
                        key3[j] = (byte)((j + 2) % 16);

                result[i] = new byte[3][]
                {
                    key1, key2, key3
                };
            }
            return result;
        }

        private static void Format(byte[] values)
        {
            List<byte> U = new List<byte>(values.Length);
            for (int i = 0; i < values.Length; i++)
                U.Add((byte)i);

            int prevIndex = 0;
            for (int i = 0; i < values.Length; i++)
            {
                int currentIndex = (prevIndex + values[i]) % U.Count;
                prevIndex = currentIndex;
                values[i] = U[currentIndex];
                U.RemoveAt(currentIndex);
            }
        }

        private static byte[] Invert(byte[] values)
        {
            byte[] result = new byte[values.Length];
            for (int i = 0; i < values.Length; i++)
                result[values[i]] = (byte)i;
            return result;
        }

        private static void MakeSingleCycle(byte[] permTable)
        {
            BitArray inCycle = new BitArray(permTable.Length, false);

            int index = 0;
            while (true)
            {
                inCycle[index] = true;
                if (inCycle[permTable[index]])
                {
                    int nextCycleStart = FirstIndexOf(inCycle, false);
                    if (nextCycleStart == -1)
                    {
                        permTable[index] = 0;
                        break;
                    }
                    else
                        permTable[index] = (byte)nextCycleStart;
                }
                index = permTable[index];
            }
        }

        public static int FirstIndexOf(BitArray bitArray, bool value)
        {
            for (int i = 0; i < bitArray.Length; i++)
                if (bitArray[i] == value)
                    return i;
            return -1;
        }

        private static byte[] TransformEmptyText(byte[][][] preliminaryKey, byte[] iv)
        {
            int blocksCount = 2304 / SizePie;

            byte[] buf = new byte[SizePie];
            byte[] result = new byte[2304];

            for (int i = 0; i < blocksCount; i++)
            {
                EncryptCBC(buf, iv, preliminaryKey, 0, result, i * SizePie);
            }
            return result;
        }
    }
}

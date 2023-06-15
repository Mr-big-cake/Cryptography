using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Controls;

namespace _Alice
{
    public static class Encryptor
    {
        #region Поля класса
        static Encryptor()
        {
            IV = new byte[16];
            BlockSize = 16;
            prevBlock = new byte[BlockSize];
            curBlock = new byte[BlockSize];
            GenerateIV();
        }
        public static byte[] IV;
        static long BlockSize;
        public enum EncryptionMode { ECB, CBC, CFB, OFB };
        public static EncryptionMode encryptionMode;
        public static byte[] prevBlock;
        public static byte[] curBlock;
        #endregion
        async public static void EncryptFile(string source, string dest, ProgressBar progressBar)
        {
            try
            {
                FileInfo file = new FileInfo(source);
                if (encryptionMode != EncryptionMode.ECB) Array.Copy(IV, prevBlock, prevBlock.Length);
                progressBar.Value = 0;
                using (FileStream sourcefs = File.Open(source, FileMode.Open))
                {
                    using (FileStream destfs = File.Open(dest, FileMode.Create))
                    {
                        long size = file.Length / BlockSize + (file.Length % BlockSize == 0 ? 0 : 1);
                        byte[] buf = new byte[BlockSize];
                        progressBar.Maximum = size;

                        for (long i = 0; i < size - 1; i++)
                        {
                            sourcefs.Read(buf, 0, (int)BlockSize);
                            var a1 = Encrypt(buf);
                            destfs.Write(a1, 0, a1.Length);
                            progressBar.Value++;
                            await Task.Delay(500);
                        }


                        int lastBlockSize = sourcefs.Read(buf, 0, (int)BlockSize);
                        Array.Resize(ref buf, lastBlockSize);
                        buf = MakePadding(buf); //добиваем нулями, последний байт - кол-во нулей
                        var a2 = Encrypt(buf);
                        destfs.Write(a2, 0, a2.Length);
                        progressBar.Value++;
                        await Task.Delay(500);
                    }

                }
            }
            catch
            { 
            
            }
        }
        async public static void DecryptFile(string source, string dest, ProgressBar progressBar)
        {
            try
            {
                FileInfo file = new FileInfo(source);
                progressBar.Value = 0;

                if (encryptionMode != EncryptionMode.ECB) Array.Copy(IV, prevBlock, prevBlock.Length);
                using (FileStream sourcefs = File.Open(source, FileMode.Open))
                {
                    using (FileStream destfs = File.Open(dest, FileMode.Create))
                    {
                        long size = file.Length / BlockSize + (file.Length % BlockSize == 0 ? 0 : 1);
                        byte[] buf = new byte[BlockSize];

                        progressBar.Maximum = size;
                        for (long i = 0; i < size - 2; i++)
                        {
                            sourcefs.Read(buf, 0, (int)BlockSize);
                            var a3 = Decrypt(buf);
                            destfs.Write(a3, 0, a3.Length);
                            progressBar.Value++;
                            await Task.Delay(500);
                        }
                        byte[] lastBlocks = new byte[BlockSize * 2];
                        sourcefs.Read(buf, 0, (int)BlockSize);
                        buf = Decrypt(buf);
                        progressBar.Value++;
                        await Task.Delay(500);
                        buf.CopyTo(lastBlocks, 0);
                        sourcefs.Read(buf, 0, (int)BlockSize);
                        buf = Decrypt(buf);
                        buf.CopyTo(lastBlocks, BlockSize);
                        Array.Resize(ref lastBlocks, lastBlocks.Length - 1);
                        destfs.Write(lastBlocks, 0, lastBlocks.Length);
                        progressBar.Value++;
                        await Task.Delay(500);
                    }

                }
            }
            catch { }
        }

        #region Вспомогательные функции
        public static void GenerateIV()
        {
            Random rnd = new Random();
            rnd.NextBytes(IV);
        }
        public static byte[] Decrypt(byte[] data)
        {
            byte[] res = new byte[data.Length];
            switch (encryptionMode)
            {
                case EncryptionMode.ECB:
                    {
                        List<byte[]> blocks = MakeListFromArray(data);
                        List<byte[]> list = blocks.AsParallel().AsOrdered().Select(part =>
                        {
                            return FROG.Decrypt(part);
                        }).ToList();
                        Array.Copy(MakeArrayFromList(list), res, res.Length);
                        break;
                    }
                case EncryptionMode.CBC:
                    {
                        data.CopyTo(res, 0);
                        curBlock = new byte[BlockSize];

                        for (int i = 0; i < data.Length / BlockSize; i++)
                        {
                            Array.Copy(res, i * BlockSize, curBlock, 0, BlockSize);
                            byte[] buf = XOR(prevBlock, FROG.Decrypt(curBlock));
                            Array.Copy(buf, 0, res, i * BlockSize, BlockSize);
                            Array.Copy(curBlock, prevBlock, BlockSize);
                        }

                        break;
                    }

                case EncryptionMode.OFB:
                    {
                        data.CopyTo(res, 0);
                        curBlock = new byte[BlockSize];

                        for (int i = 0; i < res.Length / BlockSize; i++)
                        {
                            Array.Copy(FROG.Encrypt(prevBlock), prevBlock, prevBlock.Length);
                            Array.Copy(res, i * BlockSize, curBlock, 0, BlockSize);
                            Array.Copy(XOR(prevBlock, curBlock), curBlock, curBlock.Length);
                            Array.Copy(curBlock, 0, res, i * BlockSize, BlockSize);
                        }
                        break;
                    }
                case EncryptionMode.CFB:
                    {
                        data.CopyTo(res, 0);
                        curBlock = new byte[BlockSize];

                        for (int i = 0; i < data.Length / BlockSize; i++)
                        {
                            Array.Copy(res, i * BlockSize, curBlock, 0, BlockSize);
                            byte[] buf = XOR(prevBlock, FROG.Decrypt(curBlock));
                            Array.Copy(buf, 0, res, i * BlockSize, BlockSize);
                            Array.Copy(curBlock, prevBlock, BlockSize);
                        }

                        break;
                    }
            }
            return res;
        }
        public static byte[] MakePadding(byte[] data)
        {
            long addingBlocks = 2 * BlockSize - data.Length % BlockSize;
            byte[] addedData = new byte[data.Length + addingBlocks];
            data.CopyTo(addedData, 0);
            addedData[addedData.Length - 1] = (byte)addingBlocks;
            return addedData;
        }
        public static byte[] Encrypt(byte[] data)
        {
            byte[] res = new byte[data.Length];
            data.CopyTo(res, 0);
            curBlock = new byte[BlockSize];
            switch (encryptionMode)
            {
                case EncryptionMode.ECB:
                    {
                        List<byte[]> blocks = MakeListFromArray(data);
                        List<byte[]> list = blocks.AsParallel().AsOrdered().Select(part =>
                        {
                            return FROG.Encrypt(part);
                        }).ToList();
                        Array.Copy(MakeArrayFromList(list), res, res.Length);
                        break;
                    }
                case EncryptionMode.CBC:
                    {
                        for (int i = 0; i < res.Length / BlockSize; i++)
                        {
                            Array.Copy(res, i * BlockSize, curBlock, 0, BlockSize);
                            Array.Copy(FROG.Encrypt(XOR(curBlock, prevBlock)), curBlock, BlockSize);
                            Array.Copy(curBlock, 0, res, i * BlockSize, BlockSize);
                            Array.Copy(curBlock, prevBlock, BlockSize);
                        }
                        break;
                    }
                case EncryptionMode.OFB:
                    {

                        for (int i = 0; i < res.Length / BlockSize; i++)
                        {
                            Array.Copy(FROG.Encrypt(prevBlock), prevBlock, prevBlock.Length);
                            Array.Copy(res, i * BlockSize, curBlock, 0, BlockSize);
                            Array.Copy(XOR(prevBlock, curBlock), curBlock, curBlock.Length);
                            Array.Copy(curBlock, 0, res, i * BlockSize, BlockSize);
                        }
                        break;
                    }
                case EncryptionMode.CFB:
                    {
                        for (int i = 0; i < res.Length / BlockSize; i++)
                        {
                            Array.Copy(res, i * BlockSize, curBlock, 0, BlockSize);
                            Array.Copy(FROG.Encrypt(XOR(curBlock, prevBlock)), curBlock, BlockSize);
                            Array.Copy(curBlock, 0, res, i * BlockSize, BlockSize);
                            Array.Copy(curBlock, prevBlock, BlockSize);
                        }
                        break;
                    }
            }
            return res;
        }
        private static List<byte[]> MakeListFromArray(byte[] data)
        {
            List<byte[]> res = new List<byte[]>();
            for (int i = 0; i < data.Length / BlockSize; i++)
            {
                res.Add(new byte[BlockSize]);
                Array.Copy(data, i * BlockSize, res[i], 0, BlockSize);
            }
            return res;
        }
        private static byte[] XOR(byte[] left, byte[] right)
        {
            byte[] res = new byte[left.Length];
            for (int i = 0; i < left.Length; i++)
            {
                res[i] = (byte)(left[i] ^ right[i]);
            }
            return res;
        }
        private static byte[] MakeArrayFromList(List<byte[]> data)
        {
            byte[] res = new byte[BlockSize * data.Count];
            for (int i = 0; i < data.Count; i++)
            {
                Array.Copy(data[i], 0, res, i * BlockSize, BlockSize);
            }
            return res;
        }
        #endregion
    }
}

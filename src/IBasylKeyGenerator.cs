using System.Security.Cryptography;
namespace BasylEncryptionStandard
{
    abstract public class IBasylKeyGenerator
    {
        private static RNGCryptoServiceProvider sRand = new RNGCryptoServiceProvider();

        abstract public byte GetRandomByte();
        abstract public void EncryptByte(ref byte byt);
        abstract public void Drop();

        /// <summary>
        /// Fills bytes.
        /// </summary>
        /// <param name="arr"></param>
        /// <param name="offset"></param>
        /// <param name="count"></param>
        virtual public void FillBytes(byte[] arr, int offset, int count)
        {
            for (int i = 0; i < count; i++)
            {
                arr[offset + i] = GetRandomByte();
            }
        }

        /// <summary>
        /// Fills the entire array with bytes.
        /// </summary>
        /// <param name="arr"></param>
        virtual public void FillBytes(byte[] arr)
        {
            for (int i = 0; i < arr.Length; i++)
            {
                arr[i] = GetRandomByte();
            }
        }

        public static byte[] GenerateRandomHash()
        {
            byte[] arr = new byte[32];
            sRand.GetBytes(arr);
            return arr;
        }
    }
}

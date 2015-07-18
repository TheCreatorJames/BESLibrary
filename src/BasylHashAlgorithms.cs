using System;
using System.IO;

namespace BasylEncryptionStandard
{
    public class BasylHashAlgorithms
    {

        public static byte[] BasylHashUno(String str, string pass, int hashSize, int keySize, int rounds, int skipOver, string additionalPass)
        {
            PseudoRandomGenerator prng = new PseudoRandomGenerator(keySize, pass, rounds);
            prng.SetRecycleKey(additionalPass);

            IBasylKeyGenerator wk = new BasylWeakKeyGenerator(prng);
            BESCipher cipher = new BESCipher(wk);
            prng.Recycle();

            foreach(char n in str)
            {
                byte q = (byte)n;
                cipher.EncryptLeft(ref q);
            }


            for (int i = 0; i < skipOver; i++)
            {
                for (int x = 0; x < 4; x++ )
                    prng.GetRandomByte();
            }

            int max = prng.GetRandomByte() * prng.GetRandomByte() + prng.GetRandomByte();
            for (int i = 0; i < max; i++)
            {
                for (int x = 0; x < 4; x++)
                    prng.GetRandomByte();
            }

            byte[] BHU = new byte[hashSize];
            wk.FillBytes(BHU, 0, BHU.Length);

            for (int i = 0; i < hashSize; i++)
            {
                BHU[i] ^= prng.GetRandomByte();
                cipher.EncryptRight(ref BHU);
            }

            return BHU;
        }

        public static byte[] BasylHashUno(Stream stream, string pass, int hashSize, int keySize, int rounds, int skipOver, string additionalPass)
        {
            PseudoRandomGenerator prng = new PseudoRandomGenerator(keySize, pass, rounds);
            prng.SetRecycleKey(additionalPass);

            BESCipher cipher = new BESCipher(new BasylWeakKeyGenerator(prng));
            prng.Recycle();

            byte[] buff = new byte[65536];
            while(stream.Position + 65536 < stream.Length)
            {
                stream.Read(buff, 0, 65536);
                cipher.EncryptLeft(ref buff);
            }

            int x = stream.ReadByte();
            while(x != -1)
            {
                byte z = (byte)x;
                cipher.EncryptLeft(ref z);
                x = stream.ReadByte();
            }


            for(int i = 0; i < skipOver; i++)
            {
                prng.GetRandomInt();
            }

            int max  =  prng.GetRandomByte() * prng.GetRandomByte() + prng.GetRandomByte();
            for (int i = 0; i < max; i++)
            {
                prng.GetRandomInt();
            }

            byte[] BHU = new byte[hashSize];
            prng.FillBytes(BHU);

            for (int i = 0; i < hashSize; i++)
            {
                BHU[i] ^= prng.GetRandomByte();
                cipher.EncryptRight(ref BHU);
            }

            return BHU;
        }


    }
}

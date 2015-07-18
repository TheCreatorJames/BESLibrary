using System.Security.Cryptography;
namespace BasylEncryptionStandard
{
    /// <summary>
    /// The cipher encrypts in such a way that no file is susceptible to a manipulated plaintext attack.
    /// It would be extremely difficult, and no traceable key can be derived from a plaintext file.
    /// This makes the hash checking step a little less necessary, which is somewhat required by standard BES.
    /// </summary>
    public class BESCipher
    {
        private byte[] cipher;
        private byte[] cipherB;
        private IBasylKeyGenerator generator;

        public BESCipher(IBasylKeyGenerator generator)
        {
            cipher = new byte[256];
            cipherB = new byte[256];

            for (int i = 0; i <= 255; i++)
            {
                cipherB[i] = cipher[i] = (byte)i;
            }


            this.generator = generator;
            Shuffle(10);
        }

        public IBasylKeyGenerator GetKeyGenerator()
        {
            return generator;
        }

        public void Shuffle(int times)
        {
            byte b;
            byte pos;
            for (int j = 0; j < times; j++)
            {
                for (int i = 0; i <= 255; i++)
                {
                    pos = generator.GetRandomByte();
                    b = cipher[pos];
                    cipher[pos] = cipher[i];
                    cipher[i] = b;
                }
            }

            RefreshOther();
            
        }

        private void RefreshOther()
        {
            for (int i = 0; i <= 255; i++)
            {
                cipherB[cipher[i]] = (byte)i;
            }
        }

   


        public void ShufflePosition(byte pos)
        {
            byte pos2 = generator.GetRandomByte();
            if(pos == pos2)
            {
                RefreshOther();
                return;
            }

            cipherB[cipher[pos2]] = pos;
            cipherB[cipher[pos]] = pos2;

            byte b = cipher[pos2]; 
            cipher[pos2] = cipher[pos];
            cipher[pos] = b;
        }

      
        public void EncryptRight(ref byte byt)
        {
            byte pos = byt;
            byt = cipher[byt];
            ShufflePosition(pos);
        }

        public void EncryptLeft(ref byte byt)
        {
           
            byt = cipherB[byt];

            ShufflePosition(byt);
            
        }


        public void EncryptRight(ref byte[] byt)
        {
            for (int i = 0; i < byt.Length; i++)
            {
                EncryptRight(ref byt[i]);
            }
        }


        public void EncryptLeft(ref byte[] byt)
        {
            for(int i = 0; i < byt.Length; i++)
            {
                EncryptLeft(ref byt[i]);
            }
        }

    }
}

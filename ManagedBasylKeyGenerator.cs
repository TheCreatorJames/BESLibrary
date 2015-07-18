using System;

namespace BasylEncryptionStandard
{
    public class ManagedBasylKeyGenerator : IBasylKeyGenerator
    {
        private ManagedBES.ManagedBasylKeyGenerator keyGen;

        public ManagedBasylKeyGenerator(String pass)
        {
            keyGen = new ManagedBES.ManagedBasylKeyGenerator(pass);
        }

        public ManagedBasylKeyGenerator(String pass, int initial, int rounds, int leftoff, int expansion, string additionalKey)
        {
            keyGen = new ManagedBES.ManagedBasylKeyGenerator(pass, initial, rounds, leftoff, expansion, additionalKey);
        }

        public ManagedBasylKeyGenerator(String pass, int initial, int rounds, int leftoff, int expansion, string additionalKey, byte[] sha, byte[] Key1Random, byte[] Key2Random, bool encryptedKey1)
        {
            keyGen = new ManagedBES.ManagedBasylKeyGenerator(pass, initial, rounds, leftoff, expansion, additionalKey, sha, Key1Random, Key2Random, encryptedKey1);
        }

        public override byte GetRandomByte()
        {
            return keyGen.GetRandomByte();
        }

        public override void EncryptByte(ref byte byt)
        {
            keyGen.GetRandomByte();
        }

        public override void Drop()
        { 
        }
    }
}

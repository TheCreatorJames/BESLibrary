namespace BasylEncryptionStandard
{
    public class ManagedBasylWeakKeyGenerator : IBasylKeyGenerator
    {
        private ManagedBES.ManagedPseudoRandomGenerator prng;

        public ManagedBasylWeakKeyGenerator(ManagedBES.ManagedPseudoRandomGenerator prng)
        {
            this.prng = prng;
        }

        public ManagedBES.ManagedPseudoRandomGenerator GetPseudoRandomGenerator()
        {
            return prng;
        }

        public override byte GetRandomByte()
        {
            return prng.GetRandomByte();  
        }

        public override void EncryptByte(ref byte byt)
        {
            byt ^= GetRandomByte();
        }

        public override void Drop()
        {
            prng.Drop();
        }
    }
}

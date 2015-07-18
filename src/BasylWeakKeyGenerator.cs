namespace BasylEncryptionStandard
{
    /// <summary>
    /// Takes the Basyl Pseudorandom Generator and converts it into a Key Generator.
    /// Not absolutely recommended.
    /// </summary>
    public class BasylWeakKeyGenerator : IBasylKeyGenerator
    {
        private PseudoRandomGenerator prg;
        
        public BasylWeakKeyGenerator(PseudoRandomGenerator prg)
        {
            this.prg = prg;
        }

        public PseudoRandomGenerator GetPseudoRandomGenerator()
        {
            return prg;
        }

        public override byte GetRandomByte()
        {
            return prg.GetRandomByte();
        }

        public override void EncryptByte(ref byte byt)
        {
            byt ^= GetRandomByte();
        }

        public override void Drop()
        {
            prg.Drop();
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BasylEncryptionStandard
{
    /// <summary>
    /// This is an example of how you could vastly improve the encryption scheme with some simple 
    /// shuffling. This was inspired by the lightweight improvements to BESJS.
    /// </summary>
    public class StrongerBasylPseudoAdaptor : SeedFunctionStringAdaptor
    {


        public StrongerBasylPseudoAdaptor() : base("pos * pos + 2 * pos + pos * pos * pos + seed * pos + seed")
        {
        }

        public StrongerBasylPseudoAdaptor(String function) : base(function)
        {
        }

        /// <summary>
        /// Returns a position to swap.
        /// </summary>
        /// <param name="current"></param>
        /// <param name="depth"></param>
        /// <returns></returns>
        private int Layers(List<ulong> x, ulong current, ulong depth)
        {
            if (depth <= 0)
            {
                return (int)(current % (ulong)x.Count);   
            }

            return Layers(x, x[(int)(current % (ulong)x.Count)], depth - 1);
        }

  

        public override void Shuffle(List<ulong> x, int round)
        {

            if (round % 100 == 2)
            {
                for (int i = 0; i < x.Count; i++)
                {
                    var temporary = x[i];
                    var otherPosition = Layers(x, x[i], ((temporary << 2) ^ (temporary >> 2)) % 8 + 1);
                    OddSwap(x, i, otherPosition);
                }

            }
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BasylEncryptionStandard
{
    /// <summary>
    /// This class allows you to modify the default behaviour of the PRNG class.
    /// You should implement this class and override the methods, and use the appropriate PRNG constructor.
    /// </summary>
    public class BasylPseudoAdaptator
    {
        /// <summary>
        /// This is a swap that can be overridden for different behaviour.
        /// It doesn't necessarily need to swap in this step.
        /// Default behaviour just swaps them.
        /// </summary>
        /// <param name="b1"></param>
        /// <param name="b2"></param>
        public virtual void OddSwap(List<UInt64> x, int pos1, int pos2)
        {
            ulong temp = x[pos1];
            x[pos1] = x[pos2];
            x[pos2] = temp;
        }

        /// <summary>
        /// Doesn't necessarily have to do anything. You could leave it empty. This just adds an extra step 
        /// in the generation scheme. By default it is empty.
        /// </summary>
        /// <param name="x">What will be passed in by the PRNG to Shuffle.</param>
        /// <param name="round">What round it is.</param>
        public virtual void Shuffle(List<UInt64> x, int round)
        {
        }

        /// <summary>
        /// What is called when recycling.
        /// </summary>
        /// <param name="x"></param>
        public virtual void Recycle(List<UInt64> x)
        {
        }

        /// <summary>
        /// Used to seed the generation array.
        /// Should be changed out for various programs.
        /// </summary>
        /// <param name="pos"></param>
        /// <param name="seed"></param>
        /// <returns></returns>
        public virtual ulong SeedFunction(ulong pos, ulong seed)
        {
            return pos * pos + 2 * pos + pos * pos * pos + seed * pos + seed;
        }


    }
}

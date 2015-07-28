using System;
using System.Collections.Generic;
using System.IO;

namespace BasylEncryptionStandard
{
    /// <summary>
    /// This is a high entropy Random Generator.
    /// This is one designed by Jesse Mitchell.
    /// Quite a few of the versions are also cryptographically secure.
    /// </summary>
    public class PseudoRandomGenerator
    {
        private List<UInt64> Generation;
        private int rounds;
        private int position;
        private string recycleKey;
        private byte[] seedKey;
        private byte[] SHASeedKey;

        private BasylPseudoAdaptator basylPseudoAdaptor;

        private Boolean stopRecycle;
        private int leftoff;

        public PseudoRandomGenerator() : this(1024*16) //16 KB.
        {
           
        }

        public PseudoRandomGenerator(int size) : this(size, (DateTime.Now.ToString()))
        {
           
        }

        public PseudoRandomGenerator(int size, string key) : this(size, key, 1105)
        {
        }

        public PseudoRandomGenerator(int size, string key, int rounds) : this(size, key, rounds, new BasylPseudoAdaptator())
        {
            
        }

        public PseudoRandomGenerator(int size, string key, int rounds, BasylPseudoAdaptator basylPseudoAdaptor)
        {
            position = 0;
            this.rounds = rounds;
            Generation = new List<ulong>();
            this.recycleKey = "";
            ResizeBoth(size);
            this.basylPseudoAdaptor = basylPseudoAdaptor;
            Generate(key);
        }

        /// <summary>
        /// Writes the PRNG to a file.
        /// </summary>
        /// <param name="writer"></param>
        internal void WriteToFile(BinaryWriter writer)
        {
            foreach(ulong l in Generation)
            {
                writer.Write(l);
            }
        }


        /// <summary>
        /// Resizes the list for generating.
        /// </summary>
        /// <param name="size"></param>
        private void ResizeGeneration(int size)
        {
            while(Generation.Count < size)
            {
                Generation.Add(0);
            }

        }

        /// <summary>
        /// Resizes both lists at the same time.
        /// </summary>
        /// <param name="size"></param>
        private void ResizeBoth(int size)
        {
            //ResizeGenerated(size);
            ResizeGeneration(size);
        }

        /// <summary>
        /// Stops the recycling of the values.
        /// </summary>
        public void StopRecycling()
        {
            stopRecycle = true;
        }

        /// <summary>
        /// Sets whether there is recycling or not.
        /// </summary>
        /// <param name="n"></param>
        public void SetRecycling(bool n)
        {
            this.stopRecycle = !n;
        }





        /// <summary>
        /// Sets the SHA seed to enhance encryption.
        /// </summary>
        /// <param name="sha"></param>
        public void SetSHA(byte[] sha)
        {
            this.SHASeedKey = sha;
        }

        /// <summary>
        /// Sets the extra seed to enhance encryption.
        /// </summary>
        /// <param name="key"></param>
        public void SetSeedKey(byte[] key)
        {
            this.seedKey = key;
        }


        /// <summary>
        /// Sets a string as a seed to enhance encryption
        /// </summary>
        /// <param name="r"></param>
        public void SetRecycleKey(string r)
        {
            this.recycleKey = r;
        }


        /// <summary>
        /// Sets how many of the bytes generated are left out. Enhances unpredictability.
        /// </summary>
        /// <param name="left"></param>
        public void SetLeftoff(int left)
        {
            this.leftoff = left;
        }

        /// <summary>
        /// Expands the key.
        /// </summary>
        /// <param name="times"></param>
        public void ExpandKey(uint times)
        {
            if (times == 0) return; //This is a bug fix that I can no longer remove without compatibility issues );
            List<ulong> expander = new List<ulong>();


            for(uint k = 0; k < times; k++)
            {
                Generation[0] += times;
                Generation[2] += k;
                Generation[3] += times + k + (ulong)expander.Count;
                Generation[4] += (ulong)Generation.Count;

                if (k % 2 == 0)
                    Cipher();
                else
                    CipherB();

                expander.AddRange(Generation);

            }

            Generation = expander;
        }
       

        /// <summary>
        /// Generate the Random Data using the key.
        /// </summary>
        /// <param name="key"></param>
        private void Generate(string key)
        {
            ulong seed = 1;
            char[] keyN = key.ToCharArray();
            Generation[0] = (uint)Generation.Count;

            int pos = 0;
            //Seed the array with the password, and also make the seed.
            foreach(char let in keyN)
            {
                Generation[pos++ + 1] += let;
                seed += let;
            }
            
            //Seed the data with generated values from a seed function.
            for(uint i = 0; i < Generation.Count; i++)
            {
                Generation[(int)i] += (SeedFunction(i, seed));
            }

            //Cipher it.
            for(int i = 0; i < rounds; i++)
            {
                basylPseudoAdaptor.Shuffle(Generation, rounds);
                if (i % 2 == 0)
                    Cipher();
                else
                    CipherB();
            }

      
        }

        /// <summary>
        /// This method will mutate the data again for a new fresh start.
        /// </summary>
        public void Recycle()
        {
            Recycle(false);
        }

        /// <summary>
        /// This method will mutate the data again for a new fresh start.
        /// </summary>
        private void Recycle(bool enhanced)
        {
           
            if (enhanced)
            {
                Cipher(position);
            }
            else
            {
                //Add the recycle key to the Generation Scheme.
                for (int i = 0; i < recycleKey.Length; i++)
                {

                    Generation[i] += recycleKey[i];
                }

                //Add the SHA to the Generation Scheme
                if (SHASeedKey != null)
                {
                    for (int i = 0; i < SHASeedKey.Length; i++)
                    {

                        Generation[i] += SHASeedKey[i];

                    }

                }

                //add the seed key to the generation scheme.
                if (seedKey != null)
                {
                    for (int i = 0; i < seedKey.Length; i++)
                    {
                        Generation[i] += seedKey[i];
                    }
                }
            }

            

            for (int i = 0;i < 1;i++) //could be adjusted
            {
                if (!(enhanced && i == 0))
                {
                    Cipher();
                }
                CipherB();
            }

            basylPseudoAdaptor.Recycle(Generation);
            position = 0;
        }
        
        /// <summary>
        /// This method adds previous numbers in the array, and it gets moduloed and mutated
        /// through waterfalling. The process is not reversible, and generates high entropy.
        /// </summary>
        private void Cipher()
        {
            Cipher(1);
        }

        /// <summary>
        /// This method adds previous numbers in the array, and it gets moduloed and mutated
        /// through waterfalling. The process is not reversible, and generates high entropy.
        /// </summary>
        private void Cipher(int start)
        {
            for (int i = start; i < Generation.Count; i++)
            {
                Generation[i] += Generation[i - 1];
                if (Generation[i] > 400000000) Generation[i] %= 913131;
            }
        }

        /// <summary>
        /// Same here. It just does it in reverse.
        /// </summary>
        private void CipherB()
        {
            for (int i = Generation.Count - 2; i >= 0; i--)
            {
                Generation[i] += Generation[i + 1];

                if (Generation[i] > 400000000) Generation[i] %= 913131;
            }
        }

        /// <summary>
        /// Returns a random byte from the next position.
        /// </summary>
        /// <returns></returns>
        public byte GetRandomByte()
        {
            if ((position + leftoff) >= Generation.Count)
            {
                if(stopRecycle)
                {
                    position = 0;
                }
                else
                Recycle(true);
            }

            byte r = (byte)(Generation[position] % 256);
            Generation[position] += r;


            #region Speeding up the process by eliminating the loop later on
            if (position != 0)
            {
                Generation[position] += Generation[position - 1];
                if (Generation[position] > 400000000) Generation[position] %= 913131;
            }

            if(SHASeedKey != null && position < SHASeedKey.Length)
            {
                Generation[position] += SHASeedKey[position];
            }

            if(seedKey != null && position < seedKey.Length)
            {
                Generation[position] += seedKey[position];
            }

            if(position < recycleKey.Length)
            {
                Generation[position] += recycleKey[position];
            }
            #endregion

            position++;
            return r;
        }

        /// <summary>
        /// Returns a random 4 byte integer.
        /// </summary>
        /// <returns></returns>
        public int GetRandomInt()
        {
            return BitConverter.ToInt32(new byte[] { GetRandomByte(), GetRandomByte(), GetRandomByte(), GetRandomByte() }, 0);
        }


        /// <summary>
        /// Fills the array with random bytes.
        /// </summary>
        /// <param name="arr"></param>
        public void FillBytes(byte[] arr)
        {
            for(int i = 0; i < arr.Length; i++)
            {
                arr[i] = GetRandomByte();
            }
        }

        /// <summary>
        /// Drops all the values.
        /// </summary>
        public void Drop()
        {
            Generation.Clear();
        }

        /// <summary>
        /// This seeds the generation array.
        /// </summary>
        /// <param name="pos"></param>
        /// <param name="seed"></param>
        /// <returns></returns>
        private ulong SeedFunction(ulong pos, ulong seed)
        {
            return basylPseudoAdaptor.SeedFunction(pos, seed);
        }

    }
}

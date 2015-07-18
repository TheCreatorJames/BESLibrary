using System;
using System.IO;

namespace BasylEncryptionStandard
{
    /// <summary>
    /// This is not something to be seriously used. It was an experiment, using your disk to reduce RAM requirements.
    /// </summary>
    [Obsolete("This code is not truly recommended for usage. It was written for academic purposes.")]
    public class FileStreamPseudoRandomGenerator
    {

        private BinaryReader reader;
        private BinaryWriter writer;

        private int position;
        private int chunkPosition;
        private long numberOfChunks;
        private long lastChunkSize;

        //I implemented a chunking system.
        private int currentChunk;
        private const int CHUNK_SIZE = 8192*16;
        private const int PER_CHUNK = CHUNK_SIZE / 8;
        //The chunking system makes it decently fast even with a file stream.


        private int turn;
        private int leftoff;
        private string recycleKey;
        private byte[] seedKey;
        private byte[] SHASeedKey;
        private bool stopRecycle;

        private byte[] currentChunkBytes;


        private ulong lastLong;

        public FileStreamPseudoRandomGenerator(FileStream stream, PseudoRandomGenerator generator, string recycleKey, byte[] seedKey, byte[] SHASeedKey, int leftoff)
        {
            
            writer = new BinaryWriter(stream);
            reader = new BinaryReader(stream);

            this.seedKey = seedKey;
            this.SHASeedKey = SHASeedKey;
            this.recycleKey = recycleKey;

            generator.WriteToFile(writer);
            generator.Drop();
            this.leftoff = leftoff;

            this.numberOfChunks = stream.Length / CHUNK_SIZE;

            if (stream.Length % CHUNK_SIZE != 0)
            {
                this.numberOfChunks++;
                this.lastChunkSize = stream.Length % CHUNK_SIZE;
            }
            else
                this.lastChunkSize = CHUNK_SIZE;

            writer.BaseStream.Position = 0;

           
        }

        private ulong GetNextLong()
        {
            if(currentChunkBytes == null || chunkPosition >= PER_CHUNK)
            {
                if (currentChunkBytes != null)
                {
                    UpdateChunk();
                    currentChunk++;
                } 
                reader.BaseStream.Position = currentChunk * CHUNK_SIZE;
                
                if(currentChunk != numberOfChunks - 1)
                currentChunkBytes = reader.ReadBytes(CHUNK_SIZE);
                currentChunkBytes = reader.ReadBytes((int)lastChunkSize);

                chunkPosition = 0;
            }
            
            return BitConverter.ToUInt64(currentChunkBytes, chunkPosition++ * 8);
        }


        private ulong GetPreviousLong()
        {
            if(chunkPosition <= 0)
            {
                UpdateChunk();
                currentChunk--;
                


                reader.BaseStream.Position = currentChunk * CHUNK_SIZE;

                currentChunkBytes = reader.ReadBytes(CHUNK_SIZE);
                chunkPosition = PER_CHUNK;

            }
    
           return BitConverter.ToUInt64(currentChunkBytes, chunkPosition-- * 8 - 8);
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
        /// Fills the array with random bytes.
        /// </summary>
        /// <param name="arr"></param>
        public void FillBytes(byte[] arr)
        {
            for (int i = 0; i < arr.Length; i++)
            {
                arr[i] = GetRandomByte();
            }
        }

        private void UpdateChunk()
        {
            writer.BaseStream.Position = currentChunk * CHUNK_SIZE;
            writer.Write(currentChunkBytes);
        }

        

        private void UpdateCurrentLong(ulong l)
        {
            byte[] meh = BitConverter.GetBytes(l);


            for(int i = 0; i < 8; i ++)
            {
                currentChunkBytes[(chunkPosition-1) * 8 + i] = meh[i];
            }

            //writer.BaseStream.Position -= 8;
            //writer.Write(l);
        }

        /// <summary>
        /// This method adds previous numbers in the array, and it gets moduloed and mutated
        /// through waterfalling. The process is not reversible, and generates high entropy.
        /// </summary>
        private void Cipher(int start)
        {
            for (int i = start; i < reader.BaseStream.Length/8; i++)
            {
                ulong current = GetNextLong();
                current += lastLong;
                if (current > 400000000) current %= 913131;
                lastLong = current;
                UpdateCurrentLong(current);
            }
        }

         /// <summary>
        /// Same here. It just does it in reverse.
        /// </summary>
        private void CipherB()
        {
            ulong top = GetPreviousLong();
           
            for (int i = (int)(reader.BaseStream.Length/8) - 2; i >= 0; i--)
            {
                ulong current = GetPreviousLong();

                current += top;

                if (current > 400000000) current %= 913131;
                chunkPosition++;
                UpdateCurrentLong(current);
                chunkPosition--;
                top = current;
            }
        }


        /// <summary>
        /// This method will mutate the data again for a new fresh start.
        /// </summary>
        public void Recycle()
        {
            Cipher(position);

            for (int i = 0; i < 1; i++) //could be adjusted
            {
                if (i != 0)
                {
                    //Cipher();
                    //not needed yet
                }
                reader.BaseStream.Position = reader.BaseStream.Length;
                CipherB();
            }


            position = 0;
            chunkPosition = 0;
            currentChunk = 0;
            turn++;
        }

        /// <summary>
        /// Returns a random byte from the next position.
        /// </summary>
        /// <returns></returns>
        public byte GetRandomByte()
        {
            if ((position + leftoff) >= (writer.BaseStream.Length/8))
            {
                if (stopRecycle)
                {
                    position = 0;
                }
                else
                Recycle();
            }

            ulong current = GetNextLong();

            byte r = (byte)(current % 256);
            current += r;


            #region Speeding up the process by eliminating the loop later on
            if (position != 0)
            {
                current += lastLong;
                if (current > 400000000) current %= 913131;
            }

            if (SHASeedKey != null && position < SHASeedKey.Length)
            {
                current += SHASeedKey[position];
            }

            if (seedKey != null && position < seedKey.Length)
            {
                current += seedKey[position];
            }

            if (position < recycleKey.Length)
            {
                current += recycleKey[position];
            }
            #endregion

            UpdateCurrentLong(current);
            lastLong = current;
            position++;
            return r;
        }


        internal void Drop()
        {
            writer.Close();
            reader.Close();
            writer.Dispose();
            reader.Dispose();
        }
    }
}

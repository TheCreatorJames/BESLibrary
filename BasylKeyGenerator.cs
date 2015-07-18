using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;

namespace BasylEncryptionStandard
{
    public class BasylKeyGenerator : IBasylKeyGenerator
    {
        private PseudoRandomGenerator Key1;
        private PseudoRandomGenerator Key2;
        private volatile bool ended, yield;
        private bool started;
       
        private bool QUEUE_MODE = false;

        private int queue_size;
        private Queue<byte> randomBytes;

        private byte[] Key1Random, Key2Random;
        private byte[] sha;



        //Default Settings
        public const int INITIAL = 131072;
        public const int ROUNDS = 200;
        public const int LEFTOFF = 1200;
        public const int EXPANSION = 120;
        public const string ADDITIONALKEY = "ABCD";
        //End Default Settings

        
        /// <summary>
        /// Generates a Key Generator from the password.
        /// </summary>
        /// <param name="pass"></param>
        public BasylKeyGenerator(string pass) : this(pass, INITIAL, ROUNDS, LEFTOFF, EXPANSION, ADDITIONALKEY, GenerateRandomHash())
        {
        }



        /// <summary>
        /// This creates a Basyl Key Generator from the arguments..
        /// </summary>
        /// <param name="pass"></param>
        /// <param name="initial"></param>
        /// <param name="rounds"></param>
        /// <param name="leftoff"></param>
        /// <param name="expansion"></param>
        /// <param name="additionalKey"></param>
        /// <param name="sha"></param>
        /// <param name="Key1Random"></param>
        /// <param name="Key2Random"></param>
        /// <param name="encryptedKey1"></param>
        public BasylKeyGenerator(string pass, int initial, int rounds, int leftoff, int expansion, string additionalKey, byte[] sha, byte[] Key1Random, byte[] Key2Random, bool encryptedKey1)
        {
            this.sha = sha;
            this.Key2Random = Key2Random;
            
            PseudoRandomGenerator Key1 = new PseudoRandomGenerator(initial, pass, rounds);
            Key2 = new PseudoRandomGenerator(1024 * 40, pass, 400);

            //Set the left off
            Key1.SetLeftoff(leftoff);
            Key2.SetLeftoff(80);

            //Set String Recycle Key
            Key1.SetRecycleKey(additionalKey);
            Key2.SetRecycleKey(additionalKey);

            //Expand the Keys
            Key1.ExpandKey((uint)expansion);
            Key2.ExpandKey(5);

            //Set SHA
            Key1.SetSHA(sha);
            Key2.SetSHA(sha);


            //Add randomness.
            Key2.SetSeedKey(Key2Random);


            //Recycle Key 2
            Key2.Recycle();

            //Stop Recycling Key 2
            //Key2.StopRecycling();


            //Add Key 1 Randomness

            if(encryptedKey1)
            for (int i = 0; i < Key1Random.Length; i++)
            {
                Key1Random[i] ^= Key2.GetRandomByte();
            }
            this.Key1Random = Key1Random;
            Key1.SetSeedKey(Key1Random);

            //Recycle Key 1
            Key1.Recycle();

            //this.Key1 = new FilePseudoRandomGenerator(File.Open("Key1", FileMode.Create), Key1, additionalKey, Key1Random, sha, leftoff);
            this.Key1 = Key1;

        }

         
        /// <summary>
        /// This is mainly used by the Basyl Writer.
        /// </summary>
        /// <param name="pass"></param>
        /// <param name="initial"></param>
        /// <param name="rounds"></param>
        /// <param name="leftoff"></param>
        /// <param name="expansion"></param>
        /// <param name="additionalKey"></param>
        /// <param name="sha"></param>
        public BasylKeyGenerator(string pass, int initial, int rounds, int leftoff, int expansion, string additionalKey, byte[] sha)
        {
            RNGCryptoServiceProvider random = new RNGCryptoServiceProvider();

            PseudoRandomGenerator Key1 = new PseudoRandomGenerator(initial, pass, rounds);
            Key2 = new PseudoRandomGenerator(1024 * 40, pass, 400);

            Key1Random = new byte[4];
            Key2Random = new byte[4];

            //Set the left off
            Key1.SetLeftoff(leftoff);
            Key2.SetLeftoff(80);


            //Set String Recycle Key
            Key1.SetRecycleKey(additionalKey);
            Key2.SetRecycleKey(additionalKey);

            //Expand the Keys
            Key1.ExpandKey((uint)expansion);
            Key2.ExpandKey(5);


            //Generate Randomness
            random.GetBytes(Key1Random);
            random.GetBytes(Key2Random);

            //Add randomness.
            Key1.SetSeedKey(Key1Random);
            Key2.SetSeedKey(Key2Random);

            //if sha exists
            if (sha != null)
            {
                this.sha = sha;
                //Set SHA
                Key1.SetSHA(sha);
                Key2.SetSHA(sha);
            }

            //Recycle the Keys
            Key1.Recycle();
            Key2.Recycle();

            //this.Key1 = new FilePseudoRandomGenerator(File.Open("Key1", FileMode.Create), Key1, additionalKey, Key1Random, sha, leftoff);
            this.Key1 = Key1;


        }

        /// <summary>
        /// Enables Queueing Features. Great for Networking. Not for Files.
        /// Using Default Queue Size of 512KB
        /// </summary>
        public void EnableQueueMode()
        {
            EnableQueueMode(512 * 1024);
        }

        /// <summary>
        /// Enables Queueing Features. Great for Networking. Not for Files.
        /// </summary>
        public void EnableQueueMode(int size)
        {
            this.randomBytes = new Queue<byte>();
            this.QUEUE_MODE = true;
            this.queue_size = size;
        }


        /// <summary>
        /// Get Encrypted Key 1.
        /// Only works first time.
        /// </summary>
        /// <returns></returns>
        public byte[] GetEncryptedKey1Random()
        {
            byte[] a = (byte[])Key1Random.Clone();

            for(int i = 0; i < a.Length; i++)
            {
                a[i] ^= Key2.GetRandomByte();
            }

            return a;
        }

        

        /// <summary>
        /// Gets the randomizer seed of the first key.
        /// </summary>
        /// <returns></returns>
        public byte[] GetFirstRandomizer()
        {
            return Key1Random;
        }


        /// <summary>
        /// Gets the SHA used.
        /// </summary>
        /// <returns></returns>
        public byte[] GetSHA()
        {
            return sha;
        }

        /// <summary>
        /// Gets the randomizer seed of the second key.
        /// </summary>
        /// <returns></returns>
        public byte[] GetSecondRandomizer()
        {
            return Key2Random;
        }


        /// <summary>
        /// Forces the Writer to recycle the keys.
        /// </summary>
        public void ForceRecycle()
        {
            Key1.Recycle();
            Key2.Recycle();
        }

        /// <summary>
        /// Generate the Bytes.
        /// </summary>
        public void Generate()
        {

            while(!ended)
            {
                
                    if(!yield)
                    lock (randomBytes)
                    {
                        if (!ended)
                            while (randomBytes.Count < queue_size && !ended)
                            {
                                randomBytes.Enqueue((byte)(Key1.GetRandomByte() ^ Key2.GetRandomByte()));
                                if (yield) break;
                            }
                    }
                
                    if(yield) Thread.Sleep(1000);

            }

        }


        /// <summary>
        /// Sets the SHA seed used by the writer.
        /// </summary>
        /// <param name="sha"></param>
        public void SetSHA(byte[] sha)
        {
            Key1.SetSHA(sha);
            Key2.SetSHA(sha);
            this.sha = sha;
        }

        /// <summary>
        /// Sets a Recycle Key used by the Writer.
        /// </summary>
        /// <param name="r"></param>
        public void SetRecycleKey(string r)
        {
            Key1.SetRecycleKey(r);
            Key2.SetRecycleKey(r);
        }


        /// <summary>
        /// Drops the keys.
        /// </summary>
        override public void Drop()
        {
            ended = true;
            Key1.Drop();
            Key2.Drop();
        }


      

        /// <summary>
        /// Encrypt the byte passed in.
        /// </summary>
        /// <param name="byt">Byte to be encrypted</param>
        /// <returns></returns>
        override public void EncryptByte(ref byte byt)
        {
            byt ^= GetRandomByte();
        }
    

        /// <summary>
        /// Gets a random byte.
        /// </summary>
        /// <returns></returns>
        override public byte GetRandomByte()
        {
            if (QUEUE_MODE)
            {
                if (!started)
                {
                    Thread generation = new Thread(Generate);
                    generation.Start();
                    started = true;


                }

                yield = true;
                lock (randomBytes)
                {
                    yield = false;
                    if (randomBytes.Count != 0)
                         return randomBytes.Dequeue();
                    else return (byte)(Key1.GetRandomByte() ^ Key2.GetRandomByte()); //if the queue can't keep up, keep going
                }


            } else
            return (byte)(Key1.GetRandomByte() ^ Key2.GetRandomByte());
        }

    }
}

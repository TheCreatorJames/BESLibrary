using System;
using System.IO;
using System.Security.Cryptography;

namespace BasylEncryptionStandard
{
    public class BasylFileEncryption
    {
        //Speed Settings
        private const int MAX_SPEED = 256 * 256 * 256;
        private const int MIN_SPEED = 256;
        //End Speed Settings

        //Default Settings
        private const int initial = 131072;
        private const int rounds = 200;
        private const int leftoff = 1200;
        private const int expansion = 120;
        private const string additionalKey = "ABCD";
        //End Default Settings
       

        /// <summary>
        /// Provides an easy way of decrypting files.
        /// </summary>
        /// <param name="fileName">File to be decrypted.</param>
        /// <param name="pass">pass to decrypt with</param>
        public static void Decrypt(string fileName, string pass)
        {
            Decrypt(fileName, Path.GetFileNameWithoutExtension(fileName), pass);
        }

        /// <summary>
        /// Provides an easy way of decrypting files.
        /// </summary>
        /// <param name="fileName">File to be Decrypted</param>
        /// <param name="outputFile">Decrypted File output name</param>
        /// <param name="pass">Password</param>
        public static void Decrypt(string fileName, string outputFile, string pass)
        {
            Decrypt(File.OpenRead(fileName), File.Open(outputFile, FileMode.Create), pass, initial, rounds, leftoff, expansion, additionalKey);
        }



        /// <summary>
        /// Provides an easy way of encrypting files.
        /// </summary>
        /// <param name="fileName">File to be encrypted</param>
        /// <param name="pass">Password to encrypt with</param>
        public static void Encrypt(String fileName, string pass)
        {
            Encrypt(fileName, fileName + ".bes", pass);
        }

        /// <summary>
        /// Provides an easy way of encrypting files.
        /// </summary>
        /// <param name="fileName">File to be Encrypted</param>
        /// <param name="outputFile">Output file name</param>
        /// <param name="pass">Password</param>
        public static void Encrypt(string fileName, string outputFile, string pass)
        {
            Encrypt(File.OpenRead(fileName), File.Open(outputFile, FileMode.Create), pass, initial, rounds, leftoff, expansion, additionalKey);
        }

        /// <summary>
        /// Decrypts a stream with the given configuration.
        /// Not for networking.
        /// </summary>
        /// <param name="fileName">File to be encrypted</param>
        /// <param name="pass">Password</param>
        /// <param name="initial">Initial Key Size</param>
        /// <param name="rounds">Rounds of Key Generation</param>
        /// <param name="leftoff">Chunk of data left out</param>
        /// <param name="expansion">Multiplier for a key size. (Grows it).</param>
        /// <param name="additionalKey">Key to recycle</param>
        public static void Decrypt(FileStream input, Stream output, string pass, int initial, int rounds, int leftoff, int expansion, string additionalKey)
        {
                BinaryWriter writer = new BinaryWriter(output);

                byte[] hash = new byte[32];
                byte[] o = new byte[4];
                byte[] d = new byte[4];
                input.Read(hash, 0, 32);
                input.Read(o, 0, 4);
                input.Read(d, 0, 4);
                BasylReader reader = new BasylReader(input, new BasylKeyGenerator(pass, initial, rounds, leftoff, expansion, additionalKey, hash, d, o, true));
               
                //Speeds up decryption by doing the decryption in chunks.
                int speed = MAX_SPEED;
                while (speed > MIN_SPEED)
                {
                    //Decrypt Entire File in Chunks
                    while (reader.GetStream().Position + speed < reader.GetStream().Length)
                    {
                        writer.Write(reader.ReadBytes(speed));
                    }
                    speed >>= 1;
                }


                //Decrypt Entire File
                while (reader.GetStream().Position < reader.GetStream().Length)
                {
                    writer.Write(reader.ReadByte());
                }

                writer.Close();
                reader.Close();
                reader.Dispose();
                writer.Dispose();
        }

        /// <summary>
        /// Encrypts a file stream with the given configuration.
        /// Not for networking.
        /// </summary>
        /// <param name="input">Input Stream</param>
        /// <param name="output">Output Stream</param>
        /// <param name="pass">Password</param>
        /// <param name="initial">Initial Key Size</param>
        /// <param name="rounds">Rounds of Key Generation</param>
        /// <param name="leftoff">Chunk of data left out</param>
        /// <param name="expansion">Multiplier for a key size. (Grows it).</param>
        /// <param name="additionalKey">Key to recycle</param>
        private static void Encrypt(FileStream input, Stream output, string pass, int initial, int rounds, int leftoff, int expansion, string additionalKey)
        {
                BinaryReader reader = new BinaryReader(input);
                

                //The SHA guarantees that no two files will have the same key for encryption and decryption.
                byte[] sha = SHA256.Create().ComputeHash(reader.BaseStream);
                reader.BaseStream.Position = 0;

                BasylWriter writer = new BasylWriter(output, new BasylKeyGenerator(pass, initial, rounds, leftoff, expansion, additionalKey, sha), true);

                int speed = MAX_SPEED;
                while (speed > MIN_SPEED)
                {
                    //Encrypt Entire File in Chunks
                    while (reader.BaseStream.Position + speed < reader.BaseStream.Length)
                    {
                        byte[] bytes = reader.ReadBytes(speed);
                        writer.Write(bytes);
                    }
                    speed >>= 1;
                }

                while (reader.BaseStream.Position < reader.BaseStream.Length)
                {
                    writer.Write(reader.ReadByte());
                }


                writer.Close();
                writer.Dispose();
                reader.Close();
                reader.Dispose();
        }   
    }
}

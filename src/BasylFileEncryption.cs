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

     

        //Delegate for telling percentages to a GUI.
        public delegate void Callback(double p);

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
            Decrypt(File.OpenRead(fileName), File.Open(outputFile, FileMode.Create), pass, BasylKeyGenerator.INITIAL, BasylKeyGenerator.ROUNDS, BasylKeyGenerator.LEFTOFF, BasylKeyGenerator.EXPANSION, BasylKeyGenerator.ADDITIONALKEY);
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
            Encrypt(File.OpenRead(fileName), File.Open(outputFile, FileMode.Create), pass, BasylKeyGenerator.INITIAL, BasylKeyGenerator.ROUNDS, BasylKeyGenerator.LEFTOFF, BasylKeyGenerator.EXPANSION, BasylKeyGenerator.ADDITIONALKEY);
        }

        /// <summary>
        /// Decrypts a stream with the given configuration.
        /// Not for networking.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="output"></param>
        /// <param name="pass"></param>
        /// <param name="initial"></param>
        /// <param name="rounds"></param>
        /// <param name="leftoff"></param>
        /// <param name="expansion"></param>
        /// <param name="additionalKey"></param>
        public static void Decrypt(String input, String output, string pass, int initial, int rounds, int leftoff, int expansion, string additionalKey)
        {
            Decrypt(File.OpenRead(input), File.OpenWrite(output), pass, initial, rounds, leftoff, expansion, additionalKey, null);

        }

        /// <summary>
        /// Decrypts a stream with the given configuration.
        /// Not for networking.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="output"></param>
        /// <param name="pass"></param>
        /// <param name="initial"></param>
        /// <param name="rounds"></param>
        /// <param name="leftoff"></param>
        /// <param name="expansion"></param>
        /// <param name="additionalKey"></param>
        public static void Decrypt(String input, String output, string pass, int initial, int rounds, int leftoff, int expansion, string additionalKey, Callback callback)
        {
            Decrypt(File.OpenRead(input), File.OpenWrite(output), pass, initial, rounds, leftoff, expansion, additionalKey, callback);

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
        public static void Decrypt(Stream input, Stream output, string pass, int initial, int rounds, int leftoff, int expansion, string additionalKey)
        {
            Decrypt(input, output, pass, initial, rounds, leftoff, expansion, additionalKey, null);
          
        }


        /// <summary>
        /// Decrypts a stream with the given configuration.
        /// Not for networking.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="output"></param>
        /// <param name="pass"></param>
        /// <param name="initial"></param>
        /// <param name="rounds"></param>
        /// <param name="leftoff"></param>
        /// <param name="expansion"></param>
        /// <param name="additionalKey"></param>
        /// <param name="callback"></param>
        public static void Decrypt(Stream input, Stream output, string pass, int initial, int rounds, int leftoff, int expansion, string additionalKey, Callback callback)
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
                    if (callback != null)
                    {
                        callback((double)reader.GetStream().Position / reader.GetStream().Length);
                    }

                }
                speed >>= 1;
            }


            //Decrypt Entire File
            while (reader.GetStream().Position < reader.GetStream().Length)
            {
                writer.Write(reader.ReadByte());
                if (callback != null)
                {
                    callback((double)reader.GetStream().Position / reader.GetStream().Length);
                }

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
        /// <param name="input">Input File String</param>
        /// <param name="output">Output File String</param>
        /// <param name="pass">Password</param>
        /// <param name="initial">Initial Key Size</param>
        /// <param name="rounds">Rounds of Key Generation</param>
        /// <param name="leftoff">Chunk of data left out</param>
        /// <param name="expansion">Multiplier for a key size. (Grows it).</param>
        /// <param name="additionalKey">Key to recycle</param>
        public static void Encrypt(String input, String output, string pass, int initial, int rounds, int leftoff, int expansion, string additionalKey)
        {
            Encrypt(File.OpenRead(input), File.OpenWrite(output), pass, initial, rounds, leftoff, expansion, additionalKey);
        }


        /// <summary>
        /// Encrypts a file stream with the given configuration.
        /// Not for networking.
        /// </summary>
        /// <param name="input">Input File String</param>
        /// <param name="output">Output File String</param>
        /// <param name="pass">Password</param>
        /// <param name="initial">Initial Key Size</param>
        /// <param name="rounds">Rounds of Key Generation</param>
        /// <param name="leftoff">Chunk of data left out</param>
        /// <param name="expansion">Multiplier for a key size. (Grows it).</param>
        /// <param name="additionalKey">Key to recycle</param>
        public static void Encrypt(String input, String output, string pass, int initial, int rounds, int leftoff, int expansion, string additionalKey, Callback callback)
        {
            Encrypt(File.OpenRead(input), File.OpenWrite(output), pass, initial, rounds, leftoff, expansion, additionalKey, callback);
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
        public static void Encrypt(Stream input, Stream output, string pass, int initial, int rounds, int leftoff, int expansion, string additionalKey)
        {
            Encrypt(input, output, pass, initial, rounds, leftoff, expansion, additionalKey, null);
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
        /// <param name="callback">Callback method</param>
        public static void Encrypt(Stream input, Stream output, string pass, int initial, int rounds, int leftoff, int expansion, string additionalKey, Callback callback)
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

                    if (callback != null)
                    {
                        callback((double)reader.BaseStream.Position / reader.BaseStream.Length);
                    }

                }
                speed >>= 1;
            }

            while (reader.BaseStream.Position < reader.BaseStream.Length)
            {
                writer.Write(reader.ReadByte());

                if (callback != null)
                {
                    callback((double)reader.BaseStream.Position / reader.BaseStream.Length);
                }

            }


            writer.Close();
            writer.Dispose();
            reader.Close();
            reader.Dispose();
        }


        /*
        public void Encrypt(string fileName, IBasylKeyGenerator bkg)
        {
            Encrypt(fileName, fileName + ".bes", bkg);
        }

        public void Encrypt(string fileName, string outputFilename, IBasylKeyGenerator bkg)
        {
            Encrypt(fileName, outputFilename, bkg, null);
        }

        public void Encrypt(Stream file, Stream outputFile, IBasylKeyGenerator bkg)
        {
            Encrypt(file, outputFile, bkg, null);
        }


        public void Encrypt(string fileName, string outputFilename, IBasylKeyGenerator bkg, Callback callback)
        {
            Encrypt(File.OpenRead(fileName), File.OpenWrite(outputFilename), bkg, callback);
        }


        public void Encrypt(Stream input, Stream output, IBasylKeyGenerator bkg, Callback callback)
        {
            BinaryReader reader = new BinaryReader(input);

            //The SHA guarantees that no two files will have the same key for encryption and decryption.
            byte[] sha = SHA256.Create().ComputeHash(reader.BaseStream);
            reader.BaseStream.Position = 0;

            BasylWriter writer = new BasylWriter(output, bkg, true);

            int speed = MAX_SPEED;
            while (speed > MIN_SPEED)
            {
                //Encrypt Entire File in Chunks
                while (reader.BaseStream.Position + speed < reader.BaseStream.Length)
                {
                    byte[] bytes = reader.ReadBytes(speed);
                    writer.Write(bytes);

                    if (callback != null)
                    {
                        callback((double)reader.BaseStream.Position / reader.BaseStream.Length);
                    }

                }
                speed >>= 1;
            }

            while (reader.BaseStream.Position < reader.BaseStream.Length)
            {
                writer.Write(reader.ReadByte());

                if (callback != null)
                {
                    callback((double)reader.BaseStream.Position / reader.BaseStream.Length);
                }

            }
            writer.Close();
            writer.Dispose();
            reader.Close();
            reader.Dispose();
        }


        */

    }
}

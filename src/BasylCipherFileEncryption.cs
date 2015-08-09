using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace BasylEncryptionStandard
{
    public class BasylCipherFileEncryption
    {
        //Speed Settings
        private const int MAX_SPEED = 256 * 256 * 256;
        private const int MIN_SPEED = 0;
        //End Speed Settings

        //Begin Encrypt


        /// <summary>
        /// Encrypts a file from given filename.
        /// </summary>
        /// <param name="fileName"></param>
        /// <param name="pass"></param>
        public static void Encrypt(string fileName, string pass)
        {
            Encrypt(fileName, fileName + ".bcs", pass);
        }


        /// <summary>
        /// Encrypts a file from given filename to given filename.
        /// </summary>
        /// <param name="fileName"></param>
        /// <param name="outputFileName"></param>
        /// <param name="pass"></param>
        public static void Encrypt(string fileName, string outputFileName, string pass)
        {
            Encrypt(fileName, outputFileName, pass, BasylKeyGenerator.INITIAL, BasylKeyGenerator.ROUNDS, BasylKeyGenerator.LEFTOFF, BasylKeyGenerator.EXPANSION, BasylKeyGenerator.ADDITIONALKEY);
        }

        /// <summary>
        /// Encrypts a file with the parameters.
        /// </summary>
        /// <param name="fileName"></param>
        /// <param name="outputFileName"></param>
        /// <param name="pass"></param>
        /// <param name="initial"></param>
        /// <param name="rounds"></param>
        /// <param name="leftoff"></param>
        /// <param name="expansion"></param>
        /// <param name="additionalKey"></param>
        public static void Encrypt(string fileName, string outputFileName, string pass, int initial, int rounds, int leftoff, int expansion, string additionalKey)
        {
            Encrypt(fileName, outputFileName, pass, initial, rounds, leftoff, expansion, additionalKey, null);
        }



        /// <summary>
        /// Encrypts a file with the parameters
        /// </summary>
        /// <param name="fileName"></param>
        /// <param name="outputFileName"></param>
        /// <param name="pass"></param>
        /// <param name="initial"></param>
        /// <param name="rounds"></param>
        /// <param name="leftoff"></param>
        /// <param name="expansion"></param>
        /// <param name="additionalKey"></param>
        /// <param name="callback"></param>
        public static void Encrypt(string fileName, string outputFileName, string pass, int initial, int rounds, int leftoff, int expansion, string additionalKey, BasylFileEncryption.Callback callback)
        {
            Encrypt(File.OpenRead(fileName), File.OpenWrite(outputFileName), pass, initial, rounds, leftoff, expansion, additionalKey, callback);
        }

        /// <summary>
        /// Encrypts a file with the parameters
        /// </summary>
        /// <param name="fileName"></param>
        /// <param name="outputFileName"></param>
        /// <param name="pass"></param>
        /// <param name="initial"></param>
        /// <param name="rounds"></param>
        /// <param name="leftoff"></param>
        /// <param name="expansion"></param>
        /// <param name="additionalKey"></param>
        /// <param name="callback"></param>
        /// <param name="adaptor"></param>
        public static void Encrypt(string fileName, string outputFileName, string pass, int initial, int rounds, int leftoff, int expansion, string additionalKey, BasylFileEncryption.Callback callback, BasylPseudoAdaptor adaptor)
        {
            Encrypt(File.OpenRead(fileName), File.OpenWrite(outputFileName), pass, initial, rounds, leftoff, expansion, additionalKey, callback, adaptor);
        }

        /// <summary>
        /// Encrypts a file from the parameters.
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
        public static void Encrypt(Stream input, Stream output, string pass, int initial, int rounds, int leftoff, int expansion, string additionalKey, BasylFileEncryption.Callback callback)
        {
            Encrypt(input, output, pass, initial, rounds, leftoff, expansion, additionalKey, callback, null);
        }

        /// <summary>
        /// Encrypts a file from the parameters.
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
        /// <param name="adaptor"></param>
        public static void Encrypt(Stream input, Stream output, string pass, int initial, int rounds, int leftoff, int expansion, string additionalKey, BasylFileEncryption.Callback callback, BasylPseudoAdaptor adaptor)
        {
            //The SHA guarantees that no two files will have the same key for encryption and decryption.
            byte[] sha = SHA256.Create().ComputeHash(input);
            input.Position = 0;
            BasylKeyGenerator bkg = new BasylKeyGenerator(pass, initial, rounds, leftoff, expansion, additionalKey, sha, adaptor);

            //write out the necessary randomized info.
            output.Write(sha, 0, 32);
            output.Write(bkg.GetSecondRandomizer(), 0, 4);
            output.Write(bkg.GetEncryptedKey1Random(), 0, 4);


            BESCipher cipher = new BESCipher(bkg);

            int speed = MAX_SPEED;
            while (speed > MIN_SPEED)
            {
                //Encrypt Entire File in Chunks
                byte[] buffer = new byte[speed];
                while (input.Position + speed <= input.Length)
                {
                    input.Read(buffer, 0, speed);

                    cipher.EncryptRight(ref buffer);
                    output.Write(buffer, 0, speed);

                    if (callback != null)
                    {
                        callback((double)input.Position / input.Length);
                    }

                }
                speed >>= 1;
            }

            input.Close();
            output.Close();
         

        }


        //End Encrypt
        //Begin Decrypt


            /// <summary>
            /// Decrypts a file from the filename.
            /// </summary>
            /// <param name="fileName"></param>
            /// <param name="pass"></param>
        public static void Decrypt(string fileName, string pass)
        {
            Decrypt(fileName, fileName.Substring(0,fileName.IndexOf(Path.GetExtension(fileName))), pass);
        }


        /// <summary>
        /// Decrypts a file to another given file.
        /// </summary>
        /// <param name="fileName"></param>
        /// <param name="outputFileName"></param>
        /// <param name="pass"></param>
        public static void Decrypt(string fileName, string outputFileName, string pass)
        {
            Decrypt(fileName, outputFileName, pass, BasylKeyGenerator.INITIAL, BasylKeyGenerator.ROUNDS, BasylKeyGenerator.LEFTOFF, BasylKeyGenerator.EXPANSION, BasylKeyGenerator.ADDITIONALKEY);
        }

        /// <summary>
        /// Decrypts a file with the parameters.
        /// </summary>
        /// <param name="fileName"></param>
        /// <param name="outputFileName"></param>
        /// <param name="pass"></param>
        /// <param name="initial"></param>
        /// <param name="rounds"></param>
        /// <param name="leftoff"></param>
        /// <param name="expansion"></param>
        /// <param name="additionalKey"></param>
        public static void Decrypt(string fileName, string outputFileName, string pass, int initial, int rounds, int leftoff, int expansion, string additionalKey)
        {
            Decrypt(fileName, outputFileName, pass, initial, rounds, leftoff, expansion, additionalKey, null);
        }



        /// <summary>
        /// Decrypts a file with the parameters.
        /// </summary>
        /// <param name="fileName"></param>
        /// <param name="outputFileName"></param>
        /// <param name="pass"></param>
        /// <param name="initial"></param>
        /// <param name="rounds"></param>
        /// <param name="leftoff"></param>
        /// <param name="expansion"></param>
        /// <param name="additionalKey"></param>
        /// <param name="callback"></param>
        public static void Decrypt(string fileName, string outputFileName, string pass, int initial, int rounds, int leftoff, int expansion, string additionalKey, BasylFileEncryption.Callback callback)
        {
            Decrypt(File.OpenRead(fileName), File.OpenWrite(outputFileName), pass, initial, rounds, leftoff, expansion, additionalKey, callback);
        }

        /// <summary>
        /// Decrypts a file with the parameters.
        /// </summary>
        /// <param name="fileName"></param>
        /// <param name="outputFileName"></param>
        /// <param name="pass"></param>
        /// <param name="initial"></param>
        /// <param name="rounds"></param>
        /// <param name="leftoff"></param>
        /// <param name="expansion"></param>
        /// <param name="additionalKey"></param>
        /// <param name="callback"></param>
        /// <param name="adaptor"></param>
        public static void Decrypt(string fileName, string outputFileName, string pass, int initial, int rounds, int leftoff, int expansion, string additionalKey, BasylFileEncryption.Callback callback, BasylPseudoAdaptor adaptor)
        {
            Decrypt(File.OpenRead(fileName), File.OpenWrite(outputFileName), pass, initial, rounds, leftoff, expansion, additionalKey, callback, adaptor);
        }

        /// <summary>
        /// Decrypts a file with the parameters.
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
        public static void Decrypt(Stream input, Stream output, string pass, int initial, int rounds, int leftoff, int expansion, string additionalKey, BasylFileEncryption.Callback callback)
        {
            Decrypt(input, output, pass, initial, rounds, leftoff, expansion, additionalKey, callback, null);
        }

        /// <summary>
        /// Decrypts a file with the parameters.
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
        public static void Decrypt(Stream input, Stream output, string pass, int initial, int rounds, int leftoff, int expansion, string additionalKey, BasylFileEncryption.Callback callback, BasylPseudoAdaptor adaptor)
        {
           
            //read in the necessary randomized info.
       
            byte[] sha = new byte[32];
            byte[] f = new byte[4];
            byte[] f2 = new byte[4];

            input.Read(sha, 0, 32);
            input.Read(f2, 0, 4);
            input.Read(f, 0, 4);

            BasylKeyGenerator bkg = new BasylKeyGenerator(pass, initial, rounds, leftoff, expansion, additionalKey, sha, f, f2, true, adaptor);
            BESCipher cipher = new BESCipher(bkg);

            int speed = MAX_SPEED;
            while (speed > MIN_SPEED)
            {
                //Encrypt Entire File in Chunks
                byte[] buffer = new byte[speed];
                while (input.Position + speed <= input.Length)
                {
                    input.Read(buffer, 0, speed);

                    cipher.EncryptLeft(ref buffer);
                    output.Write(buffer, 0, speed);

                    if (callback != null)
                    {
                        callback((double)input.Position / input.Length);
                    }

                }
                speed >>= 1;
            }

            input.Close();
            output.Close();
        }




    }
}

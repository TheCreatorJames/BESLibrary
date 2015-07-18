using System;
using System.IO;
using System.Text;
namespace BasylEncryptionStandard
{
    public class BasylWriter : IDisposable
    {
        private Encoding encodingSetting;
        private BinaryWriter writer;

        private IBasylKeyGenerator keyGen;


        /// <summary>
        /// Creates a Basyl Writer from the Stream and Key Generator.
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="keyGen"></param>
        /// <param name="export">Only set to true if you have yet to use the Key Generator.
        /// Otherwise, export stuff manually.</param>
        public BasylWriter(Stream stream, IBasylKeyGenerator keyGen, bool export)
        {
            encodingSetting = Encoding.Unicode;
            writer = new BinaryWriter(stream);
            this.keyGen = keyGen;


            if(export)
            {
                writer.Write(((BasylKeyGenerator)keyGen).GetSHA());
                writer.Write(((BasylKeyGenerator)keyGen).GetSecondRandomizer());
                writer.Write(((BasylKeyGenerator)keyGen).GetEncryptedKey1Random());
            }

        }

        public BasylWriter(Stream stream, IBasylKeyGenerator keyGen) : this(stream, keyGen, false)
        {

        }


        
        /// <summary>
        /// Creates a Writer from the Reader and shares its key.
        /// </summary>
        /// <param name="s"></param>
        /// <param name="reader"></param>
        /// <returns></returns>
        public static BasylWriter CreateFrom(Stream s, BasylReader reader)
        {
            BasylWriter writer = new BasylWriter(s, reader.GetKeyGenerator());
            return writer;
        }
        

        /// <summary>
        /// Sets the default encoding to use on strings.
        /// </summary>
        /// <param name="enc"></param>
        public void SetEncoding(Encoding enc)
        {
            this.encodingSetting = enc;
        }


        /// <summary>
        /// Writes an encrypted string line using the default encoding setting. Also writes length first.
        /// </summary>
        /// <param name="s"></param>
        public void WriteLine(string s)
        {
            WriteLine(s, encodingSetting);
        }


        /// <summary>
        /// Writes an encrypted string line with the given encoding. Also writes length first.
        /// </summary>
        /// <param name="s"></param>
        /// <param name="enc">Encoding to be used.</param>
        public void WriteLine(string s, Encoding enc)
        {
            byte[] arr = enc.GetBytes(s);
            Write(BitConverter.GetBytes(arr.Length));
            Write(arr);
        }
        
        /// <summary>
        /// Writes the byte array unencrypted.
        /// </summary>
        /// <param name="bytes"></param>
        public void UnencryptedWrite(byte[] bytes)
        {
            writer.Write(bytes);
        }


        /// <summary>
        /// Writes the byte unencrypted.
        /// </summary>
        /// <param name="b"></param>
        public void UnencryptedWrite(byte b)
        {
            writer.Write(b);
        }

        /// <summary>
        /// Writes the byte encrypted.
        /// </summary>
        /// <param name="b"></param>
        public void Write(byte b)
        {
            b ^= keyGen.GetRandomByte();
            
            writer.Write(b);
        }


        /// <summary>
        /// Writes an encrypted array of the bytes.
        /// </summary>
        /// <param name="bytes">Array of Bytes that is encrypted.</param>
        public void Write(byte[] bytes)
        {
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] ^= keyGen.GetRandomByte();
               
            }

            writer.Write(bytes);
        }

        /// <summary>
        /// Flushes the Stream.
        /// </summary>
        public void Flush()
        {
            writer.Flush();
        }


        /// <summary>
        /// Gets the Stream from the Writer.
        /// </summary>
        /// <returns></returns>
        public Stream GetStream()
        {
            return writer.BaseStream;
        }


        /// <summary>
        /// Returns the Key Generator.
        /// </summary>
        /// <returns></returns>
        public IBasylKeyGenerator GetKeyGenerator()
        {
            return keyGen;
        }

        /// <summary>
        /// Disposes the Writer.
        /// </summary>
        public void Dispose()
        {
            writer.Dispose();
            

            keyGen.Drop();
        }

        /// <summary>
        /// Closes the Writer.
        /// </summary>
        internal void Close()
        {
            writer.Close();
        }

     
    }
}

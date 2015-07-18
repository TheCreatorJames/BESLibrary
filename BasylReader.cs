using System;
using System.IO;
using System.Text;

namespace BasylEncryptionStandard
{
    public class BasylReader : IDisposable
    {
        private BinaryReader reader;
        private Encoding encodingSetting;
        private IBasylKeyGenerator keyGen;

        
        /// <summary>
        /// Creates a Basyl Reader from the Stream and Key Generator.
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="generator"></param>
        public BasylReader(Stream stream, IBasylKeyGenerator generator)
        {
            this.encodingSetting = Encoding.Unicode;
            keyGen = generator;
            this.reader = new BinaryReader(stream);
        }

        /// <summary>
        /// Gets the position in the stream.
        /// </summary>
        /// <returns></returns>
        public long GetPosition()
        {
            return reader.BaseStream.Position;
        }

        /// <summary>
        /// Gets length of the stream.
        /// </summary>
        /// <returns></returns>
        public long GetLength()
        {
            return reader.BaseStream.Length;
        }

        /// <summary>
        /// Gets the Stream from the reader.
        /// </summary>
        /// <returns></returns>
        public Stream GetStream()
        {
            return reader.BaseStream;
        }

        /// <summary>
        /// Reads a byte. Decrypted.
        /// </summary>
        /// <returns></returns>
        public byte ReadByte()
        {
            return (byte)((reader.ReadByte() ^ keyGen.GetRandomByte()));
        }

        /// <summary>
        /// Reads a byte that is already unencrypted.
        /// </summary>
        /// <returns></returns>
        public byte ReadUnencryptedByte()
        {
            return reader.ReadByte();
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
        /// Reads a line with the default encoding.
        /// </summary>
        /// <returns></returns>
        public string ReadLine()
        {
            return ReadLine(encodingSetting);
        }

        /// <summary>
        /// Reads a line with the given encoding.
        /// </summary>
        /// <param name="enc"></param>
        /// <returns></returns>
        public string ReadLine(Encoding enc)
        {
            int size = BitConverter.ToInt32(ReadBytes(4),0);
            byte[] arr = ReadBytes(size);
            return enc.GetString(arr);
        }


        /// <summary>
        /// Reads number of bytes that are already unencrypted.
        /// </summary>
        /// <param name="count"></param>
        /// <returns></returns>
        public byte[] ReadUnencryptedBytes(int count)
        {
            return reader.ReadBytes(count);
        }

        /// <summary>
        /// Reads the number of bytes passed in, decrypted.
        /// </summary>
        /// <param name="num"></param>
        /// <returns></returns>
        public byte[] ReadBytes(int num)
        {


            byte[] bytes = reader.ReadBytes(num);
            for (int i = 0; i < num; i++)
            {
                bytes[i] ^= keyGen.GetRandomByte();
                
            }

            return bytes;
        }

        /// <summary>
        /// Disposes of the Reader.
        /// </summary>
        public void Dispose()
        {
            reader.Dispose();
            keyGen.Drop();
        }

        /// <summary>
        /// Closes the reader.
        /// </summary>
        internal void Close()
        {
            reader.Close();
        }



        /// <summary>
        /// Gets the Key Generator.
        /// </summary>
        /// <returns></returns>
        public IBasylKeyGenerator GetKeyGenerator()
        {
            return keyGen;
        }


        
        /// <summary>
        /// Creates a BasylReader from a Writer. 
        /// Completely Synchronized and Attached.
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="pass"></param>
        /// <param name="writer"></param>
        /// <returns></returns>
        public static BasylReader CreateFrom(Stream stream, BasylWriter writer)
        {
            BasylReader result = new BasylReader(stream, writer.GetKeyGenerator());
            return result;
        }
         
    }
}

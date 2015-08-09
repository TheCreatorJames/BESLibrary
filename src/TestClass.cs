using System;
using System.IO;
using System.Text;

namespace BasylEncryptionStandard
{
    class TestClass
    {

        public static string MultString(string n, int times)
        {
            StringBuilder builder = new StringBuilder(n);
            for (int i = 1; i < times; i++)
            {
                builder.Append(n);
            }
            return builder.ToString();
        }


        

        public static void Main(string[] args)
        {
            BasylKeyGenerator bkg = new BasylKeyGenerator("Hi", 1024, 900, 1240, 1024, "ABCD", new byte[(32)], new byte[(4)], new byte[(4)], false, new StrongerBasylPseudoAdaptor());

            FileStream s = File.OpenWrite("Heh.dat");
            int size = 1024*1024*25;
            byte[] m = new byte[size];
            while (true)
            {
                bkg.FillBytes(m);
                s.Write(m, 0, size);

                for(int i = 0; i < size -1; i++)
                {
                    m[i] += m[i + 1];
                }

                for (int i = size - 2; i >= 0; i--)
                {
                    m[i] += m[i + 1];
                }
                s.Write(m, 0, size);

            }


            Console.ReadLine();
        }
    }
}

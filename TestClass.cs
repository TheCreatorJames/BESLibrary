using System;
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
            var z = BasylHashAlgorithms.BasylHashUno("Hello World!", "Ugh", 32, 65535, 800, 193, "ABCD");
            foreach(var n in z)
            {
                Console.WriteLine(n);
            }

            Console.ReadLine();
        }
    }
}

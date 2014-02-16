namespace BlackFox.Cryptography.NetScrypt.Scrypt
{
    using System;
    using System.IO;
    using System.Security;

    class Program
    {
        static void Main(string[] args)
        {
            var hash = NetScrypt.HashPassword("Hello world");
            Console.WriteLine(hash);
            Console.WriteLine(NetScrypt.Verify("Hello world", hash));
            Console.WriteLine(NetScrypt.Verify("Hello_world", hash));
            //Measure();

            long maxmem = 1024;
            double maxmemfrac = 0.125;
            TimeSpan maxtime = TimeSpan.FromSeconds(5);
            /*
            long n;
            int r;
            int p;
            ParameterSelection.PickParameters(maxmem, maxmemfrac, maxtime, out n, out r, out p);
            Console.WriteLine("N = {0} r = {1} p = {2}", n, r, p);
            */

            Console.Write("Please enter passphrase: ");
            var password = ReadPassword();

            Console.WriteLine();
            Console.WriteLine("Encrypting file...");
            using(var input = new FileStream(@"E:\temp\HelloWorld.txt", FileMode.Open))
            using (var output = new FileStream(@"E:\temp\HelloWorld.txt.scrypt", FileMode.Create))
            {
                var encryption = new ScryptEncryption(password, maxmem, maxmemfrac, maxtime);
                encryption.Encrypt(input, output);
            }

            //Console.WriteLine("salsa20/8 core per seconds: {0}", ComputeCoresPerSecond());
            Console.WriteLine("Done.");
            Console.ReadLine();
        }

        static SecureString ReadPassword()
        {
            while (Console.KeyAvailable)
            {
                Console.ReadKey(true);
            }

            var result = new SecureString();
            do
            {
                var key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.Enter)
                {
                    break;
                }
                result.AppendChar(key.KeyChar);
            } while (true);

            return result;
        }
    }
}

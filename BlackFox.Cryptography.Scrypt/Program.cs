namespace BlackFox.Cryptography.NetScrypt.Scrypt
{
    using System;
    using System.Diagnostics;
    using System.Text;
    using System.Threading.Tasks;

    class Program
    {
        static void Main(string[] args)
        {
            var hash = NetScrypt.HashPassword("Hello world");
            Console.WriteLine(hash);
            Console.WriteLine(NetScrypt.Verify("Hello world", hash));
            Console.WriteLine(NetScrypt.Verify("Hello_world", hash));
            Measure();
            Console.ReadLine();
        }

        static void Measure()
        {
            var bytes = Encoding.UTF8.GetBytes("Hello world");
            var salt = SaltWithParameters.GenerateSalt(new ScryptParameters(4096, 8, 1, 32, 16));

            Stopwatch watch = Stopwatch.StartNew();
            Parallel.For(0, 300, i => NetScrypt.DeriveKey(bytes, salt));
            watch.Stop();

            Console.WriteLine("Total = {0} ms, Average = {1} ms", watch.ElapsedMilliseconds,
                watch.ElapsedMilliseconds/100);
        }
    }
}

namespace BlackFox.Cryptography.NetScrypt.Scrypt
{
    using System;
    using System.Diagnostics;
    using System.Text;
    using System.Threading.Tasks;
    using BlackFox.Cryptography.NetScrypt.Framework;

    class Program
    {
        static void Main(string[] args)
        {
            var hash = NetScrypt.HashPassword("Hello world");
            Console.WriteLine(hash);
            Console.WriteLine(NetScrypt.Verify("Hello world", hash));
            Console.WriteLine(NetScrypt.Verify("Hello_world", hash));
            //Measure();

            long maxmem = 0;
            double maxmemfrac = 0.125;
            TimeSpan maxtime = TimeSpan.FromSeconds(5);

            long n;
            int r;
            int p;
            ParameterSelection.PickParameters(maxmem, maxmemfrac, maxtime, out n, out r, out p);
            Console.WriteLine("N = {0} r = {1} p = {2}", n, r, p);

            //Console.WriteLine("salsa20/8 core per seconds: {0}", ComputeCoresPerSecond());
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

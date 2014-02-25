using System;

namespace BlackFox.Cryptography.NetScrypt.Scrypt
{
    using System.Diagnostics;
    using BlackFox.Cryptography.NetScrypt.Framework;

    class ParameterSelection
    {
        public static void PickParameters(long maxMemory, double maxMemoryPercentage, TimeSpan maxTime, out long n, out int r,
            out int p)
        {
            int logN;
            PickParametersCore(maxMemory, maxMemoryPercentage, maxTime.TotalSeconds, out logN, out r, out p);
            n = 1L << logN;
        }

        public static void PickParametersCore(long maxMemory, double maxMemoryPercentage, double maxTime, out int logN, out int r, out int p)
        {
            double maxN;

            /* Figure out how much memory to use. */
            long memlimit = GetMemoryToUseInBytes(maxMemory, maxMemoryPercentage);

            /* Figure out how fast the CPU is. */
            double opps = ComputeCoresPerSecond();
            double opslimit = opps * maxTime;

            /* Allow a minimum of 2^15 salsa20/8 cores. */
            if (opslimit < 32768)
                opslimit = 32768;

            /* Fix r = 8 for now. */
            r = 8;

            /*
             * The memory limit requires that 128Nr <= memlimit, while the CPU
             * limit requires that 4Nrp <= opslimit.  If opslimit < memlimit/32,
             * opslimit imposes the stronger limit on N.
             */
#if DEBUG
            Trace.WriteLine(string.Format("Requiring 128Nr <= {0}, 4Nrp <= {1}", memlimit, opslimit));
#endif

            if (opslimit < memlimit / 32d)
            {
                /* Set p = 1 and choose N based on the CPU limit. */
                p = 1;
                maxN = opslimit / (r * 4);
                for (logN = 1; logN < 63; logN += 1)
                {
                    if ((1L << logN) > maxN / 2)
                    {
                        break;
                    }
                }
            }
            else
            {
                /* Set N based on the memory limit. */
                maxN = memlimit / (double)(r * 128);
                for (logN = 1; logN < 63; logN += 1)
                {
                    if ((1L << logN) > maxN / 2)
                    {
                        break;
                    }
                }

                /* Choose p based on the CPU limit. */
                double maxrp = (opslimit / 4) / (1L << logN);
                if (maxrp > 0x3fffffff)
                    maxrp = 0x3fffffff;
                p = (int)(maxrp) / r;
            }

#if DEBUG
            Trace.WriteLine(string.Format("N = {0} r = {1} p = {2}", 1L << logN, r, p));
#endif
        }

        /// <summary>
        /// <para>Equivalent to <code>memtouse</code> in scrypt code.</para>
        /// </summary>
        static long GetMemoryToUseInBytes(long maxMemory, double maxMemoryPercentage)
        {
            /* Find how many memory is available. */
            var availableMemory = GetAvailableMemoryBytes();

#if DEBUG
            Trace.WriteLine(string.Format("Memory available: {0} bytes", availableMemory));
#endif

            /* Only use the specified fraction of the available memory. */
            // ReSharper disable once CompareOfFloatsByEqualityOperator
            if ((maxMemoryPercentage > 0.5) || (maxMemoryPercentage == 0.0))
            {
                maxMemoryPercentage = 0.5;
            }
            var memlimit = (long)(maxMemoryPercentage * availableMemory);

            /* Don't use more than the specified maximum. */
            if ((maxMemory > 0) && (memlimit > maxMemory))
            {
                memlimit = maxMemory;
            }

            /* But always allow at least 1 MiB. */
            if (memlimit < 1048576)
            {
                memlimit = 1048576;
            }

#if DEBUG
            Trace.WriteLine(string.Format("Allowing up to {0} memory to be used", memlimit));
#endif

            return memlimit;
        }

        static long GetAvailableMemoryBytes()
        {
            var pc = new PerformanceCounter("Memory", "Available Bytes");
            return Convert.ToInt64(pc.NextValue());
        }

        /// <summary>
        /// Find the number of salsa20/8 cores that can be executed in 1 second.
        /// <para>Equivalent to <code>scryptenc_cpuperf</code> in scrypt code.</para>
        /// </summary>
        /// <remarks>
        /// Take a little more than 1s to execute.
        /// </remarks>
        static double ComputeCoresPerSecond()
        {
            long i = 0;

            var watch = Stopwatch.StartNew();
            do
            {
                /* Do an scrypt. */
                LibScrypt.Scrypt(null, null, 128, 1, 1, 0);

                /* We invoked the salsa20/8 core 512 times. */
                i += 512;

                /* Check if we have looped for long enough. */
                if (watch.ElapsedTicks >= Stopwatch.Frequency)
                {
                    watch.Stop();
                    break;
                }
            } while (true);

            var diffd = watch.Elapsed.TotalSeconds;

            /* We can do approximately i salsa20/8 cores per diffd seconds. */
            return i / diffd;
        }
    }
}
namespace BlackFox.Cryptography.Scrypt.ScryptCommandLine
{
    using CommandLine;

    class DecryptCommandLineArgs
    {
        [Option('M', "maxmem", DefaultValue = 0,
            HelpText = "Use at most maxmem bytes of RAM to compute the derived encryption key.")]
        public long MaxMemoryBytes { get; set; }

        [Option('m', "maxmemfrac", DefaultValue = 0.125,
            HelpText = "Use at most the fraction maxmemfrac of the available RAM to compute the derived encryption key.")]
        public double MaxMemoryPercentage { get; set; }

        [Option('t', "maxtime", DefaultValue = 5,
            HelpText = "Use at most maxtime seconds of CPU time to compute the derived encryption key.")]
        public double MaxTimeSeconds { get; set; }

        [ValueOption(0)]
        public string InputFile { get; set; }

        [ValueOption(1)]
        public string OutputFile { get; set; }
    }
}
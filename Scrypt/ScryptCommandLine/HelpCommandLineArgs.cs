namespace BlackFox.Cryptography.NetScrypt.Scrypt.ScryptCommandLine
{
    using CommandLine;

    class HelpCommandLineArgs
    {
        [ValueOption(0)]
        public string Verb { get; set; }
    }
}
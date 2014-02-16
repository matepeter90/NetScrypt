namespace BlackFox.Cryptography.NetScrypt
{
    using System;

    public class SaltWithParameters
    {
        readonly byte[] salt;
        readonly ScryptParameters parameters;

        public SaltWithParameters(byte[] salt, ScryptParameters parameters)
        {
            if (salt == null) throw new ArgumentNullException("salt");
            if (parameters == null) throw new ArgumentNullException("parameters");

            if (parameters.SaltLengthBytes != salt.Length)
            {
                throw new ArgumentException(
                    string.Format("Expected {0} bytes of salt but got {1}", parameters.SaltLengthBytes, salt.Length),
                    "salt");
            }

            this.salt = salt;
            this.parameters = parameters;
        }

        public byte[] Salt
        {
            get { return (byte[])salt.Clone(); }
        }

        public ScryptParameters Parameters
        {
            get { return parameters; }
        }

        public static SaltWithParameters GenerateSalt(ScryptParameters parameters)
        {
            if (parameters == null) throw new ArgumentNullException("parameters");

            var salt = SaltGenerator.GenerateRandomSalt(parameters.SaltLengthBytes);
            return new SaltWithParameters(salt, parameters);
        }

        public static SaltWithParameters GenerateSalt()
        {
            return GenerateSalt(ScryptParameters.Default);
        }

        public override string ToString()
        {
            return HashedPasswordString.Create(this, "");
        }
    }
}
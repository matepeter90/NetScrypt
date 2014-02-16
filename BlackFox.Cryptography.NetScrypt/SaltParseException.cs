namespace BlackFox.Cryptography.NetScrypt
{
    using System;
    using System.Runtime.Serialization;

    /// <summary>
    /// Exception thrown when a SCrypt salt string is unparsable.
    /// </summary>
    [Serializable]
    public class SaltParseException : Exception
    {
        public SaltParseException()
        {
        }

        public SaltParseException(string message) : base(message)
        {
        }

        public SaltParseException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected SaltParseException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}

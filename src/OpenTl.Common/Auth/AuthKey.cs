namespace OpenTl.Common.Auth
{
    using System;

    using OpenTl.Common.Crypto;

    public class AuthKey
    {
        private readonly ulong _auxHash;

        public AuthKey(byte[] data)
        {
            Data = data;

            var hashsum = SHA1Helper.ComputeHashsum(data);
            _auxHash = BitConverter.ToUInt64(hashsum, 0);
            Id = BitConverter.ToUInt64(hashsum, 4);
        }

        public byte[] Data { get; }

        public ulong Id { get; }
    }
}
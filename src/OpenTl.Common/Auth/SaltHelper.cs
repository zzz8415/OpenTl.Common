namespace OpenTl.Common.Auth
{
    using System.Collections;
    using System.Collections.Generic;
    using System.Linq;

    using OpenTl.Common.Extesions;

    public static class SaltHelper
    {
        public static byte[] ComputeServerSalt(IEnumerable<byte> newNonce, IEnumerable<byte> serverNonce)
        {
            return new BitArray(newNonce.Take(8).ToArray()).Xor(new BitArray(serverNonce.Take(8).ToArray())).ToByteArray();
        }
    }
}
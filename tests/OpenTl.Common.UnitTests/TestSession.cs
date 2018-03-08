using OpenTl.Common.Auth;
using OpenTl.Common.Interfaces;

namespace OpenTl.Common.UnitTests
{
    public class TestSession : ISession
    {
        public ulong MessageId { get; set; }

        public int ServerTime { get; set; }

        public AuthKey AuthKey { get; set; }

        public ulong SessionId { get; set; }

        public int LastMessageId { get; set; }
        
        public int SequenceNumber { get; set; }

        public byte[] ServerSalt { get; set; }
        
        public long? UserId { get; set; }
    }
}
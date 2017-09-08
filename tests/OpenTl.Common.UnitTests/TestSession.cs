using OpenTl.Common.Auth;
using OpenTl.Common.Interfaces;

namespace OpenTl.Common.UnitTests
{
    public class TestSession: ISession
    {
        public AuthKey AuthKey { get; set; }
        
        public ulong SessionId { get; set; }
        
        public byte[] ServerSalt { get; set; }
        
        public ulong MessageId { get; set; }
        
        public int CurrentUserId { get; set; }

        public int ServerTime { get; set; }
    }
}
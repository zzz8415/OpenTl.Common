using OpenTl.Common.Auth;

namespace OpenTl.Common.Interfaces
{
    public interface ISession
    {
        AuthKey AuthKey { get; set; }
        
        ulong SessionId { get; set; }
        
        byte[] ServerSalt { get; set; }

        ulong MessageId { get; set; }

        int CurrentUserId { get; set; }
    }
}
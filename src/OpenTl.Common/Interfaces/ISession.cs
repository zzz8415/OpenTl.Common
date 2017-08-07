using OpenTl.Common.Auth;

namespace OpenTl.Common.Interfaces
{
    public interface ISession
    {
        AuthKey AuthKey { get; set; }
        
        ulong SessionId { get; set; }
        
        ulong ServerSalt { get; set; }
        
        int ServerTime { get; set; }
    }
}
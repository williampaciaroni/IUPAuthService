using System;
namespace IUPAuthService.Models.Requests
{
    public class TokenRequest
    {
        public string Kennitala { get; set; }
        public string Password { get; set; }
    }
}

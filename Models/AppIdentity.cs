using System;
using System.ComponentModel.DataAnnotations;

namespace IUPAuthService.Models
{
    public class AppIdentity
    {
        [Key]
        public string Kennitala { get; set; }
        [Required]
        public string Password { get; set; }

        public AppIdentity()
        { }

        public AppIdentity(string kennitala, string password)
        {
            this.Kennitala = kennitala;
            this.Password = password;
        }
    }
}

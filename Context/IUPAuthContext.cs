using System;
using IUPAuthService.Models;
using Microsoft.EntityFrameworkCore;

namespace IUPAuthService.Context
{
    public class IUPAuthContext : DbContext
    {
        public DbSet<AppIdentity> AppIdentities { get; set; }

        public IUPAuthContext()
        {
        }

        public IUPAuthContext(DbContextOptions<IUPAuthContext> options) : base(options)
        {
        }

        protected override void OnConfiguring(DbContextOptionsBuilder builder)
        {
            base.OnConfiguring(builder);
        }
    }
}

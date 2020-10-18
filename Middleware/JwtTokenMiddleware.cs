using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;

namespace IUPAuthService.Middleware
{
    public class JwtTokenMiddleware
    {
        public IConfiguration Configuration { get; }

        private readonly RequestDelegate next;

        public JwtTokenMiddleware(RequestDelegate next, IConfiguration configuration)
        {
            this.next = next;
            Configuration = configuration;
        }

        public async Task Invoke(HttpContext context)
        {
            context.Response.OnStarting(() =>
            {
                var identity = context.User.Identity as ClaimsIdentity;

                if (identity.IsAuthenticated)
                {
                    var token = CreateTokenForIdentity(identity);

                    context.Response.WriteAsync("{\"token\":\"" + token + "\"}");
                }
                return Task.CompletedTask;
            });

            await next.Invoke(context);
        }

        private StringValues CreateTokenForIdentity(ClaimsIdentity identity)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["SecretKeyToken"]));

            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: "IUP",
                audience: "Audience",
                claims: identity.Claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: credentials
            );

            var tokenHandler = new JwtSecurityTokenHandler();


            var serializedToken = tokenHandler.WriteToken(token);

            return serializedToken;
        }

    }
}
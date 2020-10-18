using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using IUPAuthService.Context;
using IUPAuthService.Models;
using IUPAuthService.Models.Requests;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;

namespace IUPAuthService.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AppIdentityController : ControllerBase
    {
        private readonly IUPAuthContext iupAuthContext;
        public IConfiguration Configuration { get; }

        public AppIdentityController(IUPAuthContext iupAuthContext, IConfiguration configuration)
        {
            this.iupAuthContext = iupAuthContext;
            Configuration = configuration;
        }

        [HttpPost("getToken")]
        public IActionResult GetToken([FromBody] TokenRequest tokenRequest)
        {
            if (tokenRequest.Kennitala == null || tokenRequest.Password == null)
            {
                return BadRequest();
            }
            AppIdentity currentUser = VerifyCredentials(tokenRequest.Kennitala, tokenRequest.Password);
            if (currentUser == null)
            {
                return Unauthorized();
            }

            var identity = new ClaimsIdentity(JwtBearerDefaults.AuthenticationScheme);

            identity.AddClaim(new Claim("kennitala", currentUser.Kennitala));

            HttpContext.User = new ClaimsPrincipal(identity);

            var token = CreateTokenForIdentity(identity);

            return Ok("{\"token\":\"" + token + "\"}");
        }

        private AppIdentity VerifyCredentials(string kennitala, string password)
        {
            var appId = iupAuthContext.AppIdentities.FirstOrDefault(aI =>
                aI.Kennitala == kennitala
            );

            if (appId != null)
            {
                if(BCrypt.Net.BCrypt.Verify(password, appId.Password))
                {
                    return appId;
                }
                return null;
                
            }
            else
            {
                return null;
            }
        }

        [HttpGet("checkToken")]
        public IActionResult CheckToken()
        {
            var token = HttpContext.Request.Headers["x-token"];
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();

                var validationParams = new TokenValidationParameters()
                {
                    ValidateLifetime = true,
                    ValidateAudience = false,
                    ValidateIssuer = false,
                    ValidIssuer = "IUP",
                    ValidAudience = "Audience",
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["SecretKeyToken"]))
                };

                SecurityToken validatedToken;
                IPrincipal principal = tokenHandler.ValidateToken(token, validationParams, out validatedToken);

                return Ok();
            }
            catch (Exception)
            {
                return BadRequest();
            }

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

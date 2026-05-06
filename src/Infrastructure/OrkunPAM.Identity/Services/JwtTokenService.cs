using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Identity.Services;

public interface IJwtTokenService
{
    Result<TokenPair> GenerateTokens(Guid userId, string username, string displayName,
        string authSource, IEnumerable<string> roles, IEnumerable<string> permissions, bool mfaVerified = false);
    Result<ClaimsPrincipal> ValidateToken(string token);
}

public record TokenPair(string AccessToken, string RefreshToken, DateTime AccessTokenExpiry, DateTime RefreshTokenExpiry);

public sealed class JwtTokenService : IJwtTokenService
{
    private readonly RsaSecurityKey _signingKey;
    private readonly string _issuer;
    private readonly string _audience;
    private readonly int _accessTokenMinutes;
    private readonly int _refreshTokenHours;

    public JwtTokenService(IConfiguration configuration)
    {
        // Generate RSA key (in production, load from DPAPI-protected store)
        var rsa = RSA.Create(2048);
        _signingKey = new RsaSecurityKey(rsa);

        _issuer = configuration["Jwt:Issuer"] ?? "OrkunPAM";
        _audience = configuration["Jwt:Audience"] ?? "OrkunPAM";
        _accessTokenMinutes = int.TryParse(configuration["Jwt:AccessTokenMinutes"], out var atm) ? atm : 15;
        _refreshTokenHours = int.TryParse(configuration["Jwt:RefreshTokenHours"], out var rth) ? rth : 8;
    }

    public Result<TokenPair> GenerateTokens(Guid userId, string username, string displayName,
        string authSource, IEnumerable<string> roles, IEnumerable<string> permissions, bool mfaVerified = false)
    {
        try
        {
            var now = DateTime.UtcNow;
            var accessExpiry = now.AddMinutes(_accessTokenMinutes);
            var refreshExpiry = now.AddHours(_refreshTokenHours);
            var jti = Guid.NewGuid().ToString();

            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, userId.ToString()),
                new(JwtRegisteredClaimNames.Jti, jti),
                new(JwtRegisteredClaimNames.Name, displayName ?? username),
                new("username", username),
                new("auth_source", authSource),
                new("mfa_verified", mfaVerified.ToString().ToLower()),
            };

            foreach (var role in roles)
                claims.Add(new Claim(ClaimTypes.Role, role));

            foreach (var perm in permissions)
                claims.Add(new Claim("permission", perm));

            var signingCredentials = new SigningCredentials(_signingKey, SecurityAlgorithms.RsaSha256);

            var accessToken = new JwtSecurityToken(
                issuer: _issuer,
                audience: _audience,
                claims: claims,
                notBefore: now,
                expires: accessExpiry,
                signingCredentials: signingCredentials);

            var accessTokenString = new JwtSecurityTokenHandler().WriteToken(accessToken);

            // Refresh token is an opaque random string (stored hashed in DB)
            var refreshToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

            return Result<TokenPair>.Success(new TokenPair(
                accessTokenString, refreshToken, accessExpiry, refreshExpiry));
        }
        catch (Exception ex)
        {
            return Result<TokenPair>.Failure(Error.Internal("Token generation failed", ex.Message));
        }
    }

    public Result<ClaimsPrincipal> ValidateToken(string token)
    {
        try
        {
            var handler = new JwtSecurityTokenHandler();
            var principal = handler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = _issuer,
                ValidateAudience = true,
                ValidAudience = _audience,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = _signingKey,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromSeconds(30)
            }, out _);

            return Result<ClaimsPrincipal>.Success(principal);
        }
        catch (SecurityTokenExpiredException)
        {
            return Result<ClaimsPrincipal>.Failure(Error.Unauthorized("Token expired"));
        }
        catch (Exception ex)
        {
            return Result<ClaimsPrincipal>.Failure(Error.Unauthorized($"Invalid token: {ex.Message}"));
        }
    }
}

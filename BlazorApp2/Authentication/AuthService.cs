using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

namespace BlazorApp2.Authentication;

public sealed class AuthService(UserManager<ApplicationUser> userManager, IConfiguration configuration) : IAuthService
{
	private readonly string secret = configuration["JWT:Secret"]!;
	private readonly string issuer = configuration["JWT:Issuer"]!;
	private readonly string audience = configuration["JWT:Audience"]!;
	private readonly DateTime accessTokenExpiry = DateTime.UtcNow.AddMinutes(Convert.ToDouble(configuration["JWT:AccessTokenExpiryInMinutes"]!));
	private readonly DateTime refreshTokenExpiry = DateTime.UtcNow.AddDays(Convert.ToDouble(configuration["JWT:RefreshTokenExpiryInDays"]))!;

	public async Task<TokenDTO?> LoginAsync(LoginInputModel loginInputModel)
	{
		var user = await userManager.FindByEmailAsync(loginInputModel.Email);

		if (user is null)
		{
			return null;
		}

		var result = await userManager.CheckPasswordAsync(user, loginInputModel.Password);

		if (!result)
		{
			return null;
		}

		var claims = new List<Claim>
		{
			new(ClaimTypes.NameIdentifier, user.Id),
			new(ClaimTypes.Email, loginInputModel.Email),
			new(ClaimTypes.Name, loginInputModel.Email),
			new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
		};

		var userRoles = (List<string>)await userManager.GetRolesAsync(user);

		if (userRoles.Count != 0)
		{
			userRoles.ForEach(userRole => claims.Add(new Claim(ClaimTypes.Role, userRole)));
		}

		var accessToken = GenerateAccessToken(claims);
		var refreshToken = GenerateRefreshToken();

		user.RefreshToken = refreshToken;
		user.RefreshTokenExpiry = refreshTokenExpiry;

		await userManager.UpdateAsync(user);

		return new TokenDTO(accessToken, refreshToken);
	}

	public async Task<TokenDTO?> RefreshTokensAsync(TokenDTO tokens)
	{
		SymmetricSecurityKey symmetricSecurityKey = new(Encoding.UTF8.GetBytes(secret));
		TokenValidationParameters tokenValidationParameters = new()
		{
			ValidateIssuerSigningKey = true,
			ValidateLifetime = false,
			IssuerSigningKey = symmetricSecurityKey,
			ValidIssuer = issuer,
			ValidAudience = audience,
			ClockSkew = TimeSpan.Zero
		};

		TokenValidationResult tokenValidationResult = await new JwtSecurityTokenHandler().ValidateTokenAsync(tokens.AccessToken, tokenValidationParameters);
		IEnumerable<Claim> claims = [];

		if (tokenValidationResult.SecurityToken is JwtSecurityToken jwtSecurityToken)
		{
			if (jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256Signature, StringComparison.OrdinalIgnoreCase))
			{
				claims = tokenValidationResult.ClaimsIdentity.Claims;
			}
		}

		var email = claims.FirstOrDefault(claim => claim.Type == ClaimTypes.Email)?.Value;

		if (email is null)
		{
			return null;
		}

		var user = await userManager.FindByEmailAsync(email);

		if (user is null)
		{
			return null;
		}

		if (user.RefreshToken != tokens.RefreshToken || user.RefreshTokenExpiry < DateTime.UtcNow)
		{
			return null;
		}

		var newClaims = new List<Claim>
		{
			new(ClaimTypes.NameIdentifier, user.Id),
			new(ClaimTypes.Email, email),
			new(ClaimTypes.Name, email),
			new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
		};

		var userRoles = (List<string>)await userManager.GetRolesAsync(user);

		if (userRoles.Count != 0)
		{
			userRoles.ForEach(userRole => newClaims.Add(new Claim(ClaimTypes.Role, userRole)));
		}

		var accessToken = GenerateAccessToken(newClaims);
		var refreshToken = GenerateRefreshToken();

		user.RefreshToken = refreshToken;
		user.RefreshTokenExpiry = refreshTokenExpiry;

		await userManager.UpdateAsync(user);

		return new TokenDTO(accessToken, refreshToken);
	}

	private static string GenerateRefreshToken()
	{
		byte[] randomNumber = new byte[32];
		using var randomNumberGenerator = RandomNumberGenerator.Create();
		randomNumberGenerator.GetBytes(randomNumber);

		return Convert.ToBase64String(randomNumber);
	}

	private string GenerateAccessToken(IEnumerable<Claim> claims)
	{
		var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
		var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
		var token = new JwtSecurityToken(issuer, audience, claims, expires: accessTokenExpiry, signingCredentials: creds);

		return new JwtSecurityTokenHandler().WriteToken(token);
	}
}
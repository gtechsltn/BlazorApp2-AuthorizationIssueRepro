using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;

namespace BlazorApp2.Authentication;

public sealed class JWTAuthStateProvider(ProtectedLocalStorage protectedLocalStorage, IAuthService authService) : AuthenticationStateProvider
{
	public override async Task<AuthenticationState> GetAuthenticationStateAsync()
	{
		try
		{
			var claimsIdentity = new ClaimsIdentity();
			var tokens = await protectedLocalStorage.GetAsync<TokenDTO>("tokens");

			if (!tokens.Success || tokens.Value is null)
			{
				return new AuthenticationState(new(new ClaimsIdentity()));
			}

			var accessToken = tokens.Value.AccessToken;
			var refreshToken = tokens.Value.RefreshToken;

			claimsIdentity = new(new JwtSecurityTokenHandler().ReadJwtToken(accessToken).Claims, "jwtAuthType");

			var expiryInUnixSeconds = Convert.ToInt64(claimsIdentity.FindFirst("exp")?.Value);
			var accessTokenExpiryDate = DateTimeOffset.FromUnixTimeSeconds(expiryInUnixSeconds);

			if (accessTokenExpiryDate <= DateTime.UtcNow.AddMinutes(1))
			{
				var newAccessToken = await RefreshTokenAsync(new(accessToken, refreshToken));

				claimsIdentity = !string.IsNullOrWhiteSpace(newAccessToken) ? new(new JwtSecurityTokenHandler().ReadJwtToken(accessToken).Claims, "jwtAuthType") : new();
			}

			var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);
		
			return new AuthenticationState(claimsPrincipal);
		}
		catch (CryptographicException)
		{
			return new AuthenticationState(new(new ClaimsIdentity()));
		}
	}

	public void NotifyAuthenticationState(TokenDTO? tokens = null)
	{
		var claimsIdentity = tokens is not null ? new ClaimsIdentity(new JwtSecurityTokenHandler().ReadJwtToken(tokens.AccessToken).Claims, "jwtAuthType") : new ClaimsIdentity();
		var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);
		var authStateTask = Task.FromResult(new AuthenticationState(claimsPrincipal));

		NotifyAuthenticationStateChanged(authStateTask);
	}

	private async Task<string?> RefreshTokenAsync(TokenDTO tokens)
	{
		var newTokens = await authService.RefreshTokensAsync(tokens);

		if (newTokens is null)
		{
			await protectedLocalStorage.DeleteAsync("tokens");

			return null;
		}

		await protectedLocalStorage.SetAsync("tokens", newTokens);

		return newTokens.AccessToken;
	}
}
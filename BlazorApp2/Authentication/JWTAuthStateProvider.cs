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
			ClaimsIdentity claimsIdentity = new();

			var tokens = await protectedLocalStorage.GetAsync<TokenDTO>("tokens");

			if (!tokens.Success || tokens.Value is null)
			{
				return new AuthenticationState(new(new ClaimsIdentity()));
			}

			string accessToken = tokens.Value.AccessToken;
			string refreshToken = tokens.Value.RefreshToken;

			claimsIdentity = new(new JwtSecurityTokenHandler().ReadJwtToken(accessToken).Claims, "jwtAuthType");
			DateTimeOffset accessTokenExpiry = DateTimeOffset.FromUnixTimeSeconds(long.Parse(claimsIdentity.FindFirst("exp")!.Value));

			if (accessTokenExpiry <= DateTime.UtcNow.AddMinutes(1))
			{
				string? newAccessToken = await RefreshTokenAsync(new(accessToken, refreshToken));

				claimsIdentity = !string.IsNullOrWhiteSpace(newAccessToken) ? new(new JwtSecurityTokenHandler().ReadJwtToken(accessToken).Claims, "jwtAuthType") : new();
			}

			ClaimsPrincipal claimsPrincipal = new(claimsIdentity);
			AuthenticationState authenticationState = new(claimsPrincipal);

			return authenticationState;
		}
		catch (CryptographicException)
		{
			return new AuthenticationState(new(new ClaimsIdentity()));
		}
	}

	private async Task<string?> RefreshTokenAsync(TokenDTO tokens)
	{
		var newTokens = await authService.RefreshTokensAsync(tokens);

		if (newTokens is null)
		{
			return null;
		}

		await protectedLocalStorage.SetAsync("tokens", newTokens);

		return newTokens.AccessToken;
	}

	public async Task NotifyAuthenticationStateChangedAsync()
	{
		var task = Task.FromResult(await GetAuthenticationStateAsync());

		NotifyAuthenticationStateChanged(task);
	}
}
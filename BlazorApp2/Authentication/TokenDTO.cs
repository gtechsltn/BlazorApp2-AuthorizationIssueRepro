namespace BlazorApp2.Authentication;

public sealed class TokenDTO(string accessToken, string refreshToken)
{
	public string AccessToken { get; init; } = accessToken;

	public string RefreshToken { get; init; } = refreshToken;
}
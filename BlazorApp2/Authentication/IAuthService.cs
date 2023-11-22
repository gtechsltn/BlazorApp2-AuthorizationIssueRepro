namespace BlazorApp2.Authentication;

public interface IAuthService
{
	Task<TokenDTO?> LoginAsync(LoginInputModel loginInputModel);

	Task<TokenDTO?> RefreshTokensAsync(TokenDTO tokens);
}
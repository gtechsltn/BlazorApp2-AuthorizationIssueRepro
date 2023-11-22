namespace BlazorApp2.Authentication;

public interface IUserService
{
	Task<ApplicationUser?> RegisterUserAsync(RegisterInputModel registerInputModel);
}
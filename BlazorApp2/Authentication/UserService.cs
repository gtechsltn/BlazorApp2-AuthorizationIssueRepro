using Microsoft.AspNetCore.Identity;

namespace BlazorApp2.Authentication;

public sealed class UserService(UserManager<ApplicationUser> userManager) : IUserService
{
	public async Task<ApplicationUser?> RegisterUserAsync(RegisterInputModel registerInputModel)
	{
		var user = new ApplicationUser
		{
			Email = registerInputModel.Email,
			UserName = registerInputModel.Email
		};

		var result = await userManager.CreateAsync(user, registerInputModel.Password);

		if (!result.Succeeded)
		{
			return null;
		}

		return user;
	}
}
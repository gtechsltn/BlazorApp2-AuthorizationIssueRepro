using System.ComponentModel.DataAnnotations;

namespace BlazorApp2.Authentication;

public sealed class LoginInputModel
{
	[Required]
	public string Email { get; set; } = null!;

	[Required]
	public string Password { get; set; } = null!;
}
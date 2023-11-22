using System.ComponentModel.DataAnnotations;

namespace BlazorApp2.Authentication;

public sealed class RegisterInputModel
{
	[Required]
	public string Email { get; set; } = null!;

	[Required]
	public string Password { get; set; } = null!;

	[Required]
	[Compare(nameof(Password))]
	public string ConfirmPassword { get; set; } = null!;
}
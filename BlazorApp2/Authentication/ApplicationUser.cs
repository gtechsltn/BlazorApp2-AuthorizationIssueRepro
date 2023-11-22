using Microsoft.AspNetCore.Identity;

namespace BlazorApp2.Authentication;

public sealed class ApplicationUser : IdentityUser
{
    public string? RefreshToken { get; set; }

    public DateTime? RefreshTokenExpiry { get; set;}
}
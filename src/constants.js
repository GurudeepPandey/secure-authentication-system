
export const UserRolesEnum = {
    ADMIN: "admin",
    USER: "user"
}

export const AvailableUserRoles = Object.values(UserRolesEnum);


export const UserLoginTypes = {
    EMAIL_PASSWORD: "email-password",
    GOOGLE: "google",
    GITHUB: "github",
    MICROSOFT: "microsoft"
}

export const AvailableLoginTypes = Object.values(UserLoginTypes);
package org.v.commons.utils;

import org.v.commons.dtos.RegistrationDto;
import org.v.commons.dtos.ResetPasswordDto;
import org.v.commons.exceptions.SimpleBadRequestException;

import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

public class ValidationUtility {
    public static final Pattern UUID_PATTERN = Pattern.compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$");
    private static final Pattern NUMBER_ONLY_PATTERN = Pattern.compile("^[0-9]+$");
    public static final Pattern EMAIL_PATTERN = Pattern.compile("^(?=.{1,64}@)[\\p{L}0-9]+([._+-][\\p{L}0-9]+)*@([\\p{L}0-9]+(-[\\p{L}0-9]+)*\\.)+\\p{L}{2,190}$");
    public static final Pattern USERNAME_PATTERN = Pattern.compile("^[\\p{L}0-9_-]{3,100}$");
    private static final Pattern NAME_PATTERN = Pattern.compile("^[\\p{L} .'-]+$");
    private static final Pattern PASSWORD_PATTERN = Pattern.compile("^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?]).{8,255}$");
    public static final Pattern ROLE_AND_PERMISSION_NAME_PATTERN = Pattern.compile("^[\\p{L}0-9_]+$");

    public static void validateNotNullNotBlank(String value,
                                               String fieldName) {
        if (value == null || value.isBlank()) {
            throw new SimpleBadRequestException(fieldName + " cannot be null or blank");
        }
    }

    public static void validateEmail(String email) {
        validateNotNullNotBlank(email, "Email");
        if (!EMAIL_PATTERN.matcher(email).matches()) {
            throw new SimpleBadRequestException("Email: '" + email + "' is of invalid format");
        }
    }

    public static void validateUsername(String username) {
        validateNotNullNotBlank(username, "Username");
        if (!USERNAME_PATTERN.matcher(username).matches()) {
            throw new SimpleBadRequestException("Username: '" + username + "' is invalid as it can only contain letters, digits, underscores, and hyphens and must be between 3 and 100 characters long");
        }
    }

    public static void validatePassword(String password) {
        validateNotNullNotBlank(password, "Password");
        if (!PASSWORD_PATTERN.matcher(password).matches()) {
            throw new SimpleBadRequestException("Password: '" + password + "' is invalid as it must contain at least one digit, one lowercase letter, one uppercase letter, and one special character and must be between 8 and 255 characters long");
        }
    }

    public static void validateFirstName(String firstName) {
        validateNotNullNotBlank(firstName, "First name");
        if (firstName.length() > 50) {
            throw new SimpleBadRequestException("First name must be at most 50 characters long");
        }
        if (!NAME_PATTERN.matcher(firstName).matches()) {
            throw new SimpleBadRequestException("First name: '" + firstName + "' is invalid as it can only contain letters, spaces, periods, apostrophes, and hyphens");
        }
    }

    public static void validateMiddleName(String middleName) {
        if (middleName == null) {
            return;
        }
        if (middleName.isBlank()) {
            throw new SimpleBadRequestException("Middle name cannot be blank if provided");
        }
        if (middleName.length() > 50) {
            throw new SimpleBadRequestException("Middle name must be at most 50 characters long");
        }
        if (!NAME_PATTERN.matcher(middleName).matches()) {
            throw new SimpleBadRequestException("Middle name: '" + middleName + "' is invalid as it can only contain letters, spaces, periods, apostrophes, and hyphens");
        }
    }

    public static void validateLastName(String lastName) {
        if (lastName == null) {
            return;
        }
        if (lastName.isBlank()) {
            throw new SimpleBadRequestException("Last name cannot be blank if provided");
        }
        if (lastName.length() > 50) {
            throw new SimpleBadRequestException("Last name must be at most 50 characters long");
        }
        if (!NAME_PATTERN.matcher(lastName).matches()) {
            throw new SimpleBadRequestException("Last name: '" + lastName + "' is invalid as it can only contain letters, spaces, periods, apostrophes, and hyphens");
        }
    }

    public static void validateUuid(String uuid) {
        validateNotNullNotBlank(uuid, "UUID");
        if (!UUID_PATTERN.matcher(uuid).matches()) {
            throw new SimpleBadRequestException("UUID: '" + uuid + "' is of invalid format");
        }
    }

    public static void validateOtp(String otp,
                                   int length) {
        validateNotNullNotBlank(otp, "OTP");
        if (otp.length() != length) {
            throw new SimpleBadRequestException("OTP must be exactly '" + length + "' characters long");
        }
        if (!NUMBER_ONLY_PATTERN.matcher(otp).matches()) {
            throw new SimpleBadRequestException("OTP must contain numbers only");
        }
    }

    public static void validateRoleNameOrPermissionName(String name,
                                                        String fieldName) {
        validateNotNullNotBlank(name, fieldName);
        if (name.length() > 100) {
            throw new SimpleBadRequestException(fieldName + " must be at most 100 characters long");
        }
        if (!ROLE_AND_PERMISSION_NAME_PATTERN.matcher(name).matches()) {
            throw new SimpleBadRequestException(fieldName + ": '" + name + "' is invalid as it can only contain letters, digits, and underscores");
        }
    }

    public static Set<String> validateRegistrationInputs(RegistrationDto dto) {
        Set<String> invalidInputs = new HashSet<>();
        try {
            validateUsername(dto.getUsername());
        } catch (SimpleBadRequestException ex) {
            invalidInputs.add(ex.getMessage());
        }
        try {
            validatePassword(dto.getPassword());
        } catch (SimpleBadRequestException ex) {
            invalidInputs.add(ex.getMessage());
        }
        try {
            validateEmail(dto.getEmail());
        } catch (SimpleBadRequestException ex) {
            invalidInputs.add(ex.getMessage());
        }
        try {
            validateFirstName(dto.getFirstName());
        } catch (SimpleBadRequestException ex) {
            invalidInputs.add(ex.getMessage());
        }
        try {
            validateMiddleName(dto.getMiddleName());
        } catch (SimpleBadRequestException ex) {
            invalidInputs.add(ex.getMessage());
        }
        try {
            validateLastName(dto.getLastName());
        } catch (SimpleBadRequestException ex) {
            invalidInputs.add(ex.getMessage());
        }
        return invalidInputs;
    }

    public static Set<String> validateResetPasswordInputs(ResetPasswordDto dto) {
        Set<String> invalidInputs = validateNewAndConfirmNewPassword(dto);
        try {
            validateNotNullNotBlank(dto.getUsernameOrEmailOrId(), "Username, email or ID");
        } catch (SimpleBadRequestException ex) {
            invalidInputs.add("Invalid user identifier");
        }
        try {
            validateOtp(dto.getOtpTotp(), 6);
        } catch (SimpleBadRequestException ex) {
            invalidInputs.add("Invalid Otp/Totp");
        }
        return invalidInputs;
    }

    public static Set<String> validateNewAndConfirmNewPassword(ResetPasswordDto dto) {
        Set<String> invalidInputs = new HashSet<>();
        try {
            validatePassword(dto.getNewPassword());
            if (!dto.getNewPassword().equals(dto.getConfirmNewPassword())) {
                invalidInputs.add("New password and confirm new password do not match");
            }
        } catch (SimpleBadRequestException ex) {
            invalidInputs.add("New " + ex.getMessage());
        }
        return invalidInputs;
    }
}

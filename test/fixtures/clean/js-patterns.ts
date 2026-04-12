/**
 * FP baseline: Common JS/TS patterns that should not trigger findings.
 */

// Password field names (not credential values)
const passwordConfirm = req.body.password_confirm;
const passwordInput = document.getElementById("password");
const passwordField = formSchema.fields.password;
const isPasswordValid = checkPasswordStrength(input);

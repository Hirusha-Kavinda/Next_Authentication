'use server';
import { createUser } from "@/lib/user";
import { hashUserPassword } from "@/lib/hash";
import { createAuthSession } from "@/lib/auth";
import { redirect } from "next/navigation";

export async function signup(preveState, formData) {
    const email = formData.get('email');
    const password = formData.get('password');

    let errors = {};

    if (!email.includes('@')) {
        errors.email = 'Please enter a valid email address.';
    }

    if (password.trim().length < 8) {
        errors.password = 'Password must be at least 8 characters long';
    }

    if (Object.keys(errors).length > 0) {
        return {
            errors,
        };
    }

    const hashedPassword =  hashUserPassword(password);
    try {
        const id = createUser(email, hashedPassword);
        await createAuthSession(id);
        redirect('/training');  // Moved outside the try-catch to only execute on success
    } catch (error) {
        if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
            return {
                errors: {
                    email: 'It seems like an account for the chosen email already exists.'
                }
            };
        }
        throw error;  // This will rethrow any other errors
    }
    
    // No need for the user storage step here if `redirect` is called, as the execution will stop
}

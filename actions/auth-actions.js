'use server';
import { createUser } from "@/lib/user";
import { hashUserPassword } from "@/lib/hash";

export async function signup(preveState, formData) {
    const email = formData.get('email');
    const password = formData.get('password');

    let errors = {};

    if(!email.includes('@')){
        errors.email = 'Please enter a valid email address.';
    }

    if(password.trim().length < 8){
        errors.password = 'password must be at least 8 characters long'
    }


    if (Object.keys(errors).length > 0){
        return {
            errors,
        }
    }

    const hashedPassword = hashUserPassword(password);
     createUser(email, hashedPassword)
    // store it in the database (create a new user)
}

import { Injectable } from '@nestjs/common';

@Injectable({})
export class AuthService {
  signUp() {
    return { message: 'Im sign up' };
  }
  signIn() {
    return { message: 'Im sign in' };
  }
}

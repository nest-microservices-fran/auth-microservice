import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { LoginUserDto, RegisterUserDto } from './dto';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from '../config';


@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
    
    private readonly logger = new Logger('AuthService');

    constructor(
        private readonly jwtService: JwtService
    ) {
        super()
    }
    
    onModuleInit() {
        this.$connect();
        this.logger.log('MongoDB connected');
    }

    async signJWT(payload: JwtPayload) {
        return this.jwtService.sign(payload);
    }

    async verifyToken(token: string) {
        try {
            const { sub, iat, exp, ...user } = this.jwtService.verify(token, {
                secret: envs.jwtSecret,
            });

            return {
                user: user,
                token: await this.signJWT(user),
            }
            
        } catch (err) {
            throw new RpcException({
                status: 401,
                message: 'Invalid token'
            });
        }
    }

    async registerUser(registerUserDto: RegisterUserDto) {
        const { email, password, name } = registerUserDto;
        try {
           const user = await this.user.findUnique({
            where: {
                email,
            }
           });

           if (user) {
            throw new RpcException({
                status: 400,
                message: 'User already exists'
            });
           }

           const newUser = await this.user.create({
            data: { 
                email: email, 
                password: bcrypt.hashSync(password, 10), 
                name: name 
                }
            });

            delete newUser.password;

            return {
                user: newUser,
                token: await this.signJWT(newUser),
            }
        } catch (err) {
            throw new RpcException({
                status: 400,
                message: err.message
            });
        }
    }

    async loginUser(loginUserDto: LoginUserDto) {
        const { email, password } = loginUserDto;
        try {
           const user = await this.user.findUnique({ where: { email }});

           if (!user) {
            throw new RpcException({
                status: 400,
                message: 'User not found'
            });
           }

           const isPasswordValid = bcrypt.compareSync(password, user.password);

           if (!isPasswordValid) {
                throw new RpcException({
                    status: 400,
                    message: 'User/Password not valid'
                });
           }

           delete user.password;

            return {
                user,
                token: await this.signJWT(user),
            }
        } catch (err) {
            throw new RpcException({
                status: 400,
                message: err.message
            });
        }
    }
}

import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { Request } from 'express';

export type ClientType = 'web' | 'mobile';

export const GetClientType = createParamDecorator(
  (data: unknown, ctx: ExecutionContext): ClientType => {
    const request = ctx.switchToHttp().getRequest<Request>();
    const clientTypeHeader = request.headers['x-client-type'] as string;

    if (clientTypeHeader && clientTypeHeader.toLowerCase() === 'mobile') {
      return 'mobile';
    }
    return 'web'; 
  },
);
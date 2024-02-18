import { z } from 'zod'
import { extendApi, generateSchema } from '@anatine/zod-openapi';
import { OpenAPIV3 } from 'openapi-types';

export const passkeyDomainObject = extendApi(z.object({
  passkeyDomain: extendApi(z.string().url(), {
    description: 'URL for the passkey domain',
    example: 'http://zerodev.app'
  }),
}))
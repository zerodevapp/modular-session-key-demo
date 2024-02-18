import { redisClient } from "../db"
import db, { sql } from "../db"
import { passkeyDomainObject } from "../objects/passkeyDomainObject"

class PasskeyRepository {
    static passkeyRepository: PasskeyRepository

    constructor() {
        if (PasskeyRepository.passkeyRepository) {
            return PasskeyRepository.passkeyRepository
        }
        PasskeyRepository.passkeyRepository = this
    }

    async set(key: (string | number)[], value: any, expireIn?: number) {
        const serializedKey = JSON.stringify(key)
        const valueToStore = JSON.stringify(value)

        const exists = await redisClient.exists(serializedKey)
        if (exists) {
            throw new Error("Key already exists")
        }

        if (expireIn) {
            await redisClient.setex(serializedKey, expireIn, valueToStore)
        } else {
            await redisClient.set(serializedKey, valueToStore)
        }
    }

    async get<T>(key: (string | number)[]): Promise<T | null> {
        const value = await redisClient.get(JSON.stringify(key))
        return value ? (JSON.parse(value) as T) : null
    }

    async delete(key: (string | number)[]) {
        await redisClient.del(JSON.stringify(key))
    }

    async getPasskeyDomainByProjectId(
        projectId: string
    ): Promise<string | null> {
        const result = await (
            await db
        ).maybeOne(sql.type(passkeyDomainObject)`
      SELECT passkey_domain
      FROM project_passkey
      WHERE project_id = ${projectId}
    `)
        console.log({ result })
        if (!result) {
            return null
        }
        return getDomainFromUrl(result.passkeyDomain)
        return result?.passkeyDomain || null
    }
}

export default PasskeyRepository

function getDomainFromUrl(url: string): string {
    try {
        const hostname = new URL(url).hostname
        const parts = hostname.split(".")
        const domain = parts.length > 2 ? parts[parts.length - 2] : parts[0]
        return domain
    } catch (error) {
        console.error("Invalid URL")
        return ""
    }
}

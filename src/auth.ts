import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server"
import type {
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
  WebAuthnCredential,
} from "@simplewebauthn/server"

const RP_ID = "way-to-master.workers.dev"
const ORIGIN = "https://way-to-master.workers.dev"
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30
const CHALLENGE_TTL_SECONDS = 5 * 60

type UserRow = { id: string; display_name: string }
type CredentialRow = {
  id: string
  user_id: string
  public_key: ArrayBuffer
  counter: number
  transports: string
}

export type AuthenticatedUser = UserRow

export function registrationEnabled(env: Env): boolean {
  return typeof env.REGISTER_TOKEN === "string" && env.REGISTER_TOKEN.length > 0
}

export async function hasBearerToken(request: Request, expected: string): Promise<boolean> {
  const authorization = request.headers.get("Authorization")
  if (!authorization?.startsWith("Bearer ")) return false
  const actual = new TextEncoder().encode(authorization.slice("Bearer ".length))
  const target = new TextEncoder().encode(expected)
  const actualHash = new Uint8Array(await crypto.subtle.digest("SHA-256", actual))
  const targetHash = new Uint8Array(await crypto.subtle.digest("SHA-256", target))
  let difference = actualHash.length ^ targetHash.length
  for (let index = 0; index < actualHash.length; index += 1)
    difference |= actualHash[index] ^ (targetHash[index] ?? 0)
  return difference === 0
}

function randomId(bytes = 16): string {
  const value = new Uint8Array(bytes)
  crypto.getRandomValues(value)
  return encodeBase64Url(value)
}

function encodeBase64Url(value: ArrayBuffer | Uint8Array): string {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value)
  let binary = ""
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "")
}

function decodeBase64Url(value: string): Uint8Array {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/")
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4)
  const binary = atob(padded)
  return Uint8Array.from(binary, (character) => character.charCodeAt(0))
}

function decodeCredentialId(value: string): Uint8Array<ArrayBuffer> {
  return decodeBase64Url(value) as Uint8Array<ArrayBuffer>
}

async function hash(value: string): Promise<string> {
  return encodeBase64Url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)))
}

function readChallenge(response: RegistrationResponseJSON | AuthenticationResponseJSON): string {
  const clientData = JSON.parse(
    new TextDecoder().decode(decodeBase64Url(response.response.clientDataJSON)),
  ) as {
    challenge?: string
  }
  if (!clientData.challenge) throw new Error("Missing WebAuthn challenge")
  return clientData.challenge
}

async function consumeChallenge(
  db: D1Database,
  challenge: string,
  purpose: "registration" | "authentication",
): Promise<{ userId?: string; displayName?: string }> {
  const row = await db
    .prepare(
      "SELECT user_id, display_name FROM challenges WHERE challenge = ? AND purpose = ? AND consumed_at IS NULL AND expires_at > ?",
    )
    .bind(challenge, purpose, Math.floor(Date.now() / 1000))
    .first<{ user_id: string | null; display_name: string | null }>()
  if (!row) throw new Error("Invalid or expired challenge")

  const consumed = await db
    .prepare("UPDATE challenges SET consumed_at = ? WHERE challenge = ? AND consumed_at IS NULL")
    .bind(Math.floor(Date.now() / 1000), challenge)
    .run()
  if (consumed.meta.changes !== 1) throw new Error("Challenge has already been consumed")
  return { userId: row.user_id ?? undefined, displayName: row.display_name ?? undefined }
}

async function createSession(db: D1Database, userId: string): Promise<string> {
  const token = randomId(32)
  const now = Math.floor(Date.now() / 1000)
  await db
    .prepare(
      "INSERT INTO sessions (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(await hash(token), userId, now + SESSION_TTL_SECONDS, now)
    .run()
  return token
}

export async function getSessionUser(
  db: D1Database,
  request: Request,
): Promise<AuthenticatedUser | null> {
  const token = request.headers.get("Cookie")?.match(/(?:^|; )session=([^;]+)/)?.[1]
  if (!token) return null
  const row = await db
    .prepare(
      "SELECT users.id, users.display_name FROM sessions JOIN users ON users.id = sessions.user_id WHERE sessions.token_hash = ? AND sessions.expires_at > ?",
    )
    .bind(await hash(decodeURIComponent(token)), Math.floor(Date.now() / 1000))
    .first<UserRow>()
  return row ?? null
}

function sessionCookie(token: string): string {
  return `session=${encodeURIComponent(token)}; Max-Age=${SESSION_TTL_SECONDS}; Path=/; HttpOnly; Secure; SameSite=Lax`
}

export async function registrationOptions(db: D1Database, displayName: string): Promise<Response> {
  if (!displayName.trim() || displayName.length > 80)
    return Response.json({ error: "Invalid display name" }, { status: 400 })
  const userId = randomId(16)
  const options = await generateRegistrationOptions({
    rpName: "Way to Master",
    rpID: RP_ID,
    userName: userId,
    userID: decodeCredentialId(userId),
    userDisplayName: displayName.trim(),
    timeout: CHALLENGE_TTL_SECONDS * 1000,
    attestationType: "none",
    authenticatorSelection: { residentKey: "required", userVerification: "required" },
  })
  const now = Math.floor(Date.now() / 1000)
  await db
    .prepare(
      "INSERT INTO challenges (challenge, purpose, user_id, display_name, expires_at, created_at) VALUES (?, 'registration', ?, ?, ?, ?)",
    )
    .bind(options.challenge, userId, displayName.trim(), now + CHALLENGE_TTL_SECONDS, now)
    .run()
  return Response.json(options)
}

export async function registrationVerify(
  db: D1Database,
  body: { response: RegistrationResponseJSON },
): Promise<Response> {
  const challenge = readChallenge(body.response)
  const pending = await consumeChallenge(db, challenge, "registration")
  if (!pending.displayName) throw new Error("Invalid registration state")
  const userId = pending.userId
  if (!userId) throw new Error("Invalid registration state")
  const verification = await verifyRegistrationResponse({
    response: body.response,
    expectedChallenge: challenge,
    expectedOrigin: ORIGIN,
    expectedRPID: RP_ID,
    requireUserVerification: true,
  })
  if (!verification.verified) throw new Error("WebAuthn registration failed")
  const credential = verification.registrationInfo.credential
  const now = Math.floor(Date.now() / 1000)
  await db.batch([
    db
      .prepare("INSERT INTO users (id, display_name, created_at) VALUES (?, ?, ?)")
      .bind(userId, pending.displayName, now),
    db
      .prepare(
        "INSERT INTO credentials (id, user_id, public_key, counter, transports, created_at) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .bind(
        credential.id,
        userId,
        credential.publicKey,
        credential.counter,
        JSON.stringify(credential.transports ?? []),
        now,
      ),
  ])
  const token = await createSession(db, userId)
  return Response.json({ ok: true }, { headers: { "Set-Cookie": sessionCookie(token) } })
}

export async function authenticationOptions(db: D1Database): Promise<Response> {
  const options = await generateAuthenticationOptions({ rpID: RP_ID, userVerification: "required" })
  const now = Math.floor(Date.now() / 1000)
  await db
    .prepare(
      "INSERT INTO challenges (challenge, purpose, expires_at, created_at) VALUES (?, 'authentication', ?, ?)",
    )
    .bind(options.challenge, now + CHALLENGE_TTL_SECONDS, now)
    .run()
  return Response.json(options)
}

export async function authenticationVerify(
  db: D1Database,
  body: { response: AuthenticationResponseJSON },
): Promise<Response> {
  const challenge = readChallenge(body.response)
  await consumeChallenge(db, challenge, "authentication")
  const row = await db
    .prepare("SELECT * FROM credentials WHERE id = ?")
    .bind(body.response.id)
    .first<CredentialRow>()
  if (!row) throw new Error("Unknown credential")
  const credential: WebAuthnCredential = {
    id: row.id,
    publicKey: new Uint8Array(row.public_key),
    counter: row.counter,
    transports: JSON.parse(row.transports) as string[],
  }
  const verification = await verifyAuthenticationResponse({
    response: body.response,
    expectedChallenge: challenge,
    expectedOrigin: ORIGIN,
    expectedRPID: RP_ID,
    credential,
    requireUserVerification: true,
  })
  if (!verification.verified) throw new Error("WebAuthn authentication failed")
  await db
    .prepare("UPDATE credentials SET counter = ? WHERE id = ?")
    .bind(verification.authenticationInfo.newCounter, row.id)
    .run()
  const token = await createSession(db, row.user_id)
  return Response.json({ ok: true }, { headers: { "Set-Cookie": sessionCookie(token) } })
}

export async function addCredentialOptions(db: D1Database, userId: string): Promise<Response> {
  const credentials = await db
    .prepare("SELECT id, transports FROM credentials WHERE user_id = ?")
    .bind(userId)
    .all<{ id: string; transports: string }>()
  const options = await generateRegistrationOptions({
    rpName: "Way to Master",
    rpID: RP_ID,
    userName: userId,
    userID: decodeCredentialId(userId),
    userDisplayName: userId,
    timeout: CHALLENGE_TTL_SECONDS * 1000,
    attestationType: "none",
    excludeCredentials: credentials.results.map((credential) => ({
      id: credential.id,
      transports: JSON.parse(credential.transports) as string[],
    })),
    authenticatorSelection: { residentKey: "required", userVerification: "required" },
  })
  const now = Math.floor(Date.now() / 1000)
  await db
    .prepare(
      "INSERT INTO challenges (challenge, purpose, user_id, expires_at, created_at) VALUES (?, 'registration', ?, ?, ?)",
    )
    .bind(options.challenge, userId, now + CHALLENGE_TTL_SECONDS, now)
    .run()
  return Response.json(options)
}

export async function addCredentialVerify(
  db: D1Database,
  userId: string,
  body: { response: RegistrationResponseJSON },
): Promise<Response> {
  const challenge = readChallenge(body.response)
  const pending = await consumeChallenge(db, challenge, "registration")
  if (pending.userId !== userId) throw new Error("Invalid registration owner")
  const verification = await verifyRegistrationResponse({
    response: body.response,
    expectedChallenge: challenge,
    expectedOrigin: ORIGIN,
    expectedRPID: RP_ID,
    requireUserVerification: true,
  })
  if (!verification.verified) throw new Error("WebAuthn registration failed")
  const credential = verification.registrationInfo.credential
  await db
    .prepare(
      "INSERT INTO credentials (id, user_id, public_key, counter, transports, created_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(
      credential.id,
      userId,
      credential.publicKey,
      credential.counter,
      JSON.stringify(credential.transports ?? []),
      Math.floor(Date.now() / 1000),
    )
    .run()
  return Response.json({ ok: true })
}

import {
  addCredentialOptions,
  addCredentialVerify,
  authenticationOptions,
  authenticationVerify,
  getSessionUser,
  hasBearerToken,
  registrationEnabled,
  registrationOptions,
  registrationVerify,
} from "./auth"
import { devicePage, loginPage, registrationPage } from "./pages"

async function readJson(request: Request): Promise<Record<string, unknown>> {
  const body = await request.json()
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("Invalid JSON body")
  return body as Record<string, unknown>
}

function errorResponse(error: unknown, message = "Authentication request failed"): Response {
  console.error(error)
  const detail = error instanceof Error ? error.message : String(error)
  return Response.json({ error: message, detail }, { status: 400 })
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url)

    if (url.pathname === "/api/health") {
      return Response.json({ ok: true })
    }

    if (request.method === "GET" && url.pathname === "/login") return loginPage()
    if (request.method === "GET" && url.pathname === "/register") {
      return registrationEnabled(env)
        ? registrationPage()
        : new Response("Not Found", { status: 404 })
    }

    if (url.pathname === "/api/authentication/options" && request.method === "POST") {
      try {
        return await authenticationOptions(env.DB)
      } catch (error) {
        return errorResponse(error, "Unable to start passkey sign-in")
      }
    }
    if (url.pathname === "/api/authentication/verify" && request.method === "POST") {
      try {
        return await authenticationVerify(env.DB, {
          response: (await readJson(request)).response as never,
        })
      } catch (error) {
        return errorResponse(error, "Passkey verification failed")
      }
    }

    if (url.pathname === "/api/register/options" || url.pathname === "/api/register/verify") {
      if (!registrationEnabled(env)) return new Response("Not Found", { status: 404 })
      if (!(await hasBearerToken(request, env.REGISTER_TOKEN ?? "")))
        return Response.json({ error: "Invalid registration token" }, { status: 401 })
      if (request.method !== "POST") return new Response("Method Not Allowed", { status: 405 })
      try {
        const body = await readJson(request)
        if (url.pathname.endsWith("/options")) {
          return await registrationOptions(env.DB, String(body.displayName ?? ""))
        }
        if (url.pathname.endsWith("/verify")) {
          return await registrationVerify(env.DB, { response: body.response as never })
        }
      } catch (error) {
        return errorResponse(
          error,
          url.pathname.endsWith("/options")
            ? "Unable to start registration"
            : "Passkey registration failed",
        )
      }
      return new Response("Method Not Allowed", { status: 405 })
    }

    const user = await getSessionUser(env.DB, request)
    if (!user) return Response.redirect(new URL("/login", request.url), 302)

    if (url.pathname === "/api/devices/options" && request.method === "POST") {
      return addCredentialOptions(env.DB, user.id)
    }
    if (url.pathname === "/api/devices/verify" && request.method === "POST") {
      try {
        return await addCredentialVerify(env.DB, user.id, {
          response: (await readJson(request)).response as never,
        })
      } catch (error) {
        return errorResponse(error)
      }
    }

    if (request.method === "GET" && url.pathname === "/devices") return devicePage()

    return env.ASSETS.fetch(request)
  },
} satisfies ExportedHandler<Env>

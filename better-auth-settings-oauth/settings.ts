import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { db } from "@/db";
import * as schema from "@/db/schema";
import { genericOAuth } from "better-auth/plugins";

export const auth = betterAuth({
    baseURL: process.env.NEXT_PUBLIC_BETTER_AUTH_URL || "http://localhost:3000",
    database: drizzleAdapter(db, {
        provider: "pg",
        schema: {
            user: schema.user,
            session: schema.session,
            account: schema.account,
            verification: schema.verification,
        },
    }),
    emailAndPassword: {
        enabled: true, // if you accept email and password
    },
    plugins: [
        genericOAuth({
            config: [
                {
                    providerId: "shib",
                    clientId: process.env.CLIENT_ID ?? "",
                    clientSecret: process.env.CLIENT_SECRET,
                    // once again they dont support redirection of well known, have to separate
                    authorizationUrl: "https://shib.auth.rpi.edu/idp/profile/oidc/authorize",
                    tokenUrl: "https://shib.auth.rpi.edu/idp/profile/oidc/token",
                    userInfoUrl: "https://shib.auth.rpi.edu/idp/profile/oidc/userinfo",
                    scopes: ["openid", "email", "profile"],
                    pkce: true,
                    responseMode: "query",
                    getToken: async ({ code, redirectURI, codeVerifier }) => {
                        // for some reason, basic auth doesnt work, so we have to manually do this part
                        const body = new URLSearchParams({
                            grant_type: "authorization_code",
                            code,
                            redirect_uri: redirectURI,
                        });
                        if (codeVerifier) {
                            body.set("code_verifier", codeVerifier);
                        }
                        // RFC 6749: URL-encode client_id   and secret before base64 for client_secret_basic
                        const encodedId = encodeURIComponent(process.env.CLIENT_ID ?? "");
                        const encodedSecret = encodeURIComponent(process.env.CLIENT_SECRET ?? "");
                        const credentials = Buffer.from(
                            `${encodedId}:${encodedSecret}`
                        ).toString("base64");

                        console.log('[getToken] client_id:', process.env.CLIENT_ID);
                        console.log('[getToken] redirect_uri:', redirectURI);

                        const response = await fetch(
                            "https://shib.auth.rpi.edu/idp/profile/oidc/token",
                            {
                                method: "POST",
                                headers: {
                                    "Content-Type": "application/x-www-form-urlencoded",
                                    "Accept": "application/json",
                                    "Authorization": `Basic ${credentials}`,
                                },
                                body: body.toString(),
                            }
                        );
                        // this could be condensed later...
                        const text = await response.text();
                        console.log('[getToken] status:', response.status);
                        console.log('[getToken] response:', text);
                        if (!response.ok) {
                            throw new Error(`Token request failed: ${response.status} ${text}`);
                        }
                        const data = JSON.parse(text);
                        return {
                            tokenType: data.token_type,
                            accessToken: data.access_token,
                            refreshToken: data.refresh_token,
                            idToken: data.id_token,
                            accessTokenExpiresAt: data.expires_in
                                ? new Date(Date.now() + data.expires_in * 1000)
                                : undefined,
                            refreshTokenExpiresAt: data.refresh_token_expires_in
                                ? new Date(Date.now() + data.refresh_token_expires_in * 1000)
                                : undefined,
                            scopes: data.scope
                                ? data.scope.split(" ")
                                : [],
                            raw: data,
                        };
                    },
                }
            ]
        })
    ]
});

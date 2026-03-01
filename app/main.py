#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------------
# /**
#  * @file main.py
#  * @author Oscar Gomez Fuente <oscargomezf@gmail.com>
#  * @modified Oscar Gomez Fuente <oscargomezf@gmail.com>
#  * @date 2026-02-26 17:40:00 
#  * @version v1.0
#  * @section DESCRIPTION
#  *     FastAPI + Keycloak features:
#  *       - JWT RS256 validation via JWKS (no introspection).
#  *       - Role control (realm and client).
#  *       - Swagger UI integrated with OAuth2 Authorization Code + PKCE:
#  *           * In /docs, click "Authorize" -> redirects to Keycloak -> returns to /docs/oauth2-redirect
#  *           * Swagger stores the access_token and sends it in Authorization: Bearer <token>
#  *
#  *     REQUIREMENTS:
#  *       pip install fastapi "uvicorn[standard]" "python-jose[cryptography]" httpx "pydantic>=2"
#  *
#  *     REQUIRED KEYCLOAK CONFIGURATION:
#  *       1) Realm: fastapi-demo (or your preferred name)
#  *       2) CONFIDENTIAL client for your backend (e.g., fastapi-client) -> to issue tokens from scripts/services
#  *           - Client authentication: ON (equals "confidential")
#  *           - Standard Flow: ON (and Direct Access Grants ON only if you want to test ROPC with curl/Postman)
#  *       3) PUBLIC client exclusively for Swagger UI (e.g., fastapi-swagger)
#  *           - Client authentication: OFF (equals "public")
#  *           - Standard Flow: ON
#  *           - Valid Redirect URIs: http://localhost:8001/docs/oauth2-redirect
#  *           - Web origins: http://localhost:8001
#  *           - (Optional) PKCE Required: ON, Method: S256
#  *       4) Create roles:
#  *           - Realm role: "admin"
#  *           - Client role (in fastapi-client): "report:read"
#  *       5) Assign roles to the test user (e.g., user_fastapi)
#  *
#  *     IMPORTANT NOTES:
#  *       - Validation at runtime is ALWAYS done via JWKS (signature + claims). Swagger only helps obtain and send the token.
#  *       - To enable PKCE in Swagger, we force loading Swagger UI v5 from CDN and run initOAuth with usePkceWithAuthorizationCodeGrant=True.
#  *       - VERY IMPORTANT: in the /docs HTML, <link> and <script> from CDN must load correctly; otherwise, the browser may use local assets without PKCE.
#  *
#  *     How to run:
#  *       uvicorn main:app --reload --port 8001
#  *       Open http://localhost:8001/docs (preferably in a private window the first time to avoid cache).
# -----------------------------------------------------------------------------

import os
import time
from typing import Any, Dict, List, Optional

import httpx
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.openapi.docs import get_swagger_ui_oauth2_redirect_html
from fastapi.responses import HTMLResponse
from fastapi.security import (HTTPAuthorizationCredentials, HTTPBearer, OAuth2AuthorizationCodeBearer)
from jose import jwk, jwt
from jose.exceptions import ExpiredSignatureError, JWKError, JWTClaimsError, JWTError
from pydantic import BaseModel

from fastapi.responses import JSONResponse

# -----------------------------------------------------------------------------
# 1) Keycloak Configuration
# -----------------------------------------------------------------------------
# Separate public URL (for browser/Swagger) and internal URL (for the app in Docker).
KEYCLOAK_PUBLIC_URL = os.getenv("KEYCLOAK_PUBLIC_URL")
KEYCLOAK_INTERNAL_URL = os.getenv("KEYCLOAK_INTERNAL_URL")

KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "fastapi-demo")
KEYCLOAK_AUDIENCE = os.getenv("KEYCLOAK_AUDIENCE", "fastapi-client")
CLIENT_ID_FOR_ROLES = os.getenv("CLIENT_ID_FOR_ROLES", KEYCLOAK_AUDIENCE)
ACCEPTED_ALGS = ["RS256"]

PUBLIC_ISSUER = f"{KEYCLOAK_PUBLIC_URL}/realms/{KEYCLOAK_REALM}"
INTERNAL_ISSUER = f"{KEYCLOAK_INTERNAL_URL}/realms/{KEYCLOAK_REALM}"
JWKS_URL = f"{INTERNAL_ISSUER}/protocol/openid-connect/certs"

# -----------------------------------------------------------------------------
# 2) OAuth2 (Authorization Code) for OpenAPI/Swagger UI
# -----------------------------------------------------------------------------
oauth2_scheme = OAuth2AuthorizationCodeBearer(
	authorizationUrl=f"{PUBLIC_ISSUER}/protocol/openid-connect/auth",  # [CAMBIO]
	tokenUrl=f"{PUBLIC_ISSUER}/protocol/openid-connect/token",         # [CAMBIO]
	scopes={"openid": "OpenID Connect basic scope"},
)

# -----------------------------------------------------------------------------
# 3) JWKS client (downloads and caches public keys)
# -----------------------------------------------------------------------------
class JWKSClient:
	def __init__(self, jwks_url: str, ttl_seconds: int = 300):
		self.jwks_url = jwks_url
		self.ttl_seconds = ttl_seconds
		self._keys: Optional[Dict[str, Any]] = None
		self._fetched_at: float = 0.0

	async def _refresh(self) -> None:
		async with httpx.AsyncClient(timeout=10) as client:
			resp = await client.get(self.jwks_url)
			resp.raise_for_status()
			self._keys = resp.json()
			self._fetched_at = time.time()

	async def get_key(self, kid: str) -> Dict[str, Any]:
		if self._keys is None or (time.time() - self._fetched_at) > self.ttl_seconds:
			await self._refresh()

		for k in self._keys.get("keys", []):
			if k.get("kid") == kid:
				return k

		# Second attempt in case Keycloak recently rotated keys
		await self._refresh()
		for k in self._keys.get("keys", []):
			if k.get("kid") == kid:
				return k

		raise HTTPException(status_code=401, detail="No matching JWK found for token kid.")

jwks_client = JWKSClient(JWKS_URL)

# -----------------------------------------------------------------------------
# 4) Token payload model (relevant claims)
# -----------------------------------------------------------------------------
class TokenPayload(BaseModel):
	sub: Optional[str] = None
	iss: Optional[str] = None
	aud: Optional[Any] = None
	exp: Optional[int] = None
	iat: Optional[int] = None
	nbf: Optional[int] = None
	preferred_username: Optional[str] = None
	email: Optional[str] = None
	realm_access: Optional[Dict[str, List[str]]] = None
	resource_access: Optional[Dict[str, Dict[str, List[str]]]] = None
	azp: Optional[str] = None

# -----------------------------------------------------------------------------
# 5) JWT validation (signature + claims)
# -----------------------------------------------------------------------------
bearer_scheme = HTTPBearer(auto_error=True)

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> TokenPayload:
	token = credentials.credentials
	try:
		unverified_header = jwt.get_unverified_header(token)
		kid = unverified_header.get("kid")
		if not kid:
			raise HTTPException(status_code=401, detail="Missing KID in token header.")

		jwk_data = await jwks_client.get_key(kid)

		try:
			public_key = jwk.construct(jwk_data)
			pem = public_key.to_pem().decode()
		except Exception as e:
			raise HTTPException(status_code=401, detail=f"Invalid JWK: {e}")

		payload_dict = jwt.decode(
			token,
			pem,
			algorithms=ACCEPTED_ALGS,
			audience=KEYCLOAK_AUDIENCE,
			issuer=PUBLIC_ISSUER,
			options={
				"verify_signature": True,
				"verify_iss": True,
				"verify_exp": True,
				"verify_iat": True,
				"verify_nbf": True,
				"verify_aud": True
			},
		)

		# >>> IMPORTANT <<<
		# We do NOT check 'azp' to allow tokens issued to 'fastapi-swagger'
		# (public client) when the API expects 'fastapi-client' as aud.
		# If you want to require 'azp' in the future, add:
		# azp = payload_dict.get("azp")
		# if azp and azp != KEYCLOAK_AUDIENCE:
		#     raise HTTPException(status_code=401, detail="Invalid azp claim.")

		return TokenPayload.model_validate(payload_dict)

	except ExpiredSignatureError:
		raise HTTPException(status_code=401, detail="Token expired.")
	except JWTClaimsError as e:
		raise HTTPException(status_code=401, detail=f"Invalid claims: {e}")
	except (JWKError, JWTError) as e:
		raise HTTPException(status_code=401, detail=f"Token error: {e}")

# -----------------------------------------------------------------------------
# 6) Helpers for role control (Realm roles and Client roles)
# -----------------------------------------------------------------------------
def require_realm_roles(*required: str):
	"""Requires Realm roles (realm_access.roles)."""
	async def _role_dep(user: TokenPayload = Depends(verify_token)):
		roles = (user.realm_access or {}).get("roles", []) or []
		missing = [r for r in required if r not in roles]
		if missing:
			raise HTTPException(status_code=403, detail=f"Missing realm roles: {missing}")
		return user
	return _role_dep

def require_client_roles(*required: str, client_id: Optional[str] = None):
	"""Requires client roles (resource_access[client_id].roles)."""
	client = client_id or CLIENT_ID_FOR_ROLES
	async def _role_dep(user: TokenPayload = Depends(verify_token)):
		roles = ((user.resource_access or {}).get(client, {}) or {}).get("roles", []) or []
		missing = [r for r in required if r not in roles]
		if missing:
			raise HTTPException(status_code=403, detail=f"Missing client roles: {missing}")
		return user
	return _role_dep

# -----------------------------------------------------------------------------
# 7) FastAPI + Default Docs (no custom HTML)
# -----------------------------------------------------------------------------
app = FastAPI(
	title="FastAPI + Keycloak Demo",
	version="1.0.0",
	swagger_ui_oauth2_redirect_url="/docs/oauth2-redirect",  # standard redirect used by Swagger UI
)

# This route is served by FastAPI by default with the redirect HTML
@app.get("/docs/oauth2-redirect", include_in_schema=False)
def swagger_ui_redirect():
	return get_swagger_ui_oauth2_redirect_html()

# Debug endpoint: effective configuration
@app.get("/debug/config", include_in_schema=False)
def debug_config():
	return JSONResponse({
		"KEYCLOAK_PUBLIC_URL": KEYCLOAK_PUBLIC_URL,
		"KEYCLOAK_INTERNAL_URL": KEYCLOAK_INTERNAL_URL,
		"PUBLIC_ISSUER": PUBLIC_ISSUER,
		"INTERNAL_ISSUER": INTERNAL_ISSUER,
		"JWKS_URL": JWKS_URL,
		"KEYCLOAK_REALM": KEYCLOAK_REALM,
		"KEYCLOAK_AUDIENCE": KEYCLOAK_AUDIENCE
	})

# Debug endpoint: quick JWKS test
@app.get("/debug/status", include_in_schema=False)
async def debug_status():
	status = {"jwks_url": JWKS_URL, "ok": False, "http_status": None, "note": ""}
	try:
		# follow_redirects=False to check if Keycloak tries to redirect to 'http://localhost:8080/...'
		async with httpx.AsyncClient(timeout=5, follow_redirects=False) as client:
			resp = await client.get(JWKS_URL)
			status["http_status"] = resp.status_code
			if 300 <= resp.status_code < 400:
				status["note"] = f"redirect to: {resp.headers.get('location')}"
			body = (resp.text or "")[:120]
			status["body_sample"] = body
			status["ok"] = resp.status_code == 200 and '"keys"' in body
	except Exception as e:
		status["note"] = f"error: {e.__class__.__name__}: {e}"
	return JSONResponse(status)
	
# -----------------------------------------------------------------------------
# 8) Example endpoints
# -----------------------------------------------------------------------------
@app.get("/health")
async def health():
	return {"status": "ok"}

@app.get("/public")
async def public():
	return {"msg": "This endpoint is public."}

@app.get("/protected")
async def protected(
	_oauth2: str = Security(oauth2_scheme, scopes=["openid"]),
	user: TokenPayload = Depends(verify_token),
):
	return {
		"msg": "Authenticated successfully.",
		"username": user.preferred_username,
		"email": user.email,
	}

@app.get("/admin")
async def admin(
	_oauth2: str = Security(oauth2_scheme, scopes=["openid"]),
	user: TokenPayload = Depends(require_realm_roles("admin")),
):
	return {"msg": "Welcome, administrator.", "user": user.preferred_username}

@app.get("/reports")
async def reports(
	_oauth2: str = Security(oauth2_scheme, scopes=["openid"]),
	user: TokenPayload = Depends(require_client_roles("report:read")),
):
	return {"msg": "Access to report:read granted.", "user": user.preferred_username}

# -----------------------------------------------------------------------------
# 9) MAIN
# -----------------------------------------------------------------------------
if __name__ == "__main__":
	uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=False)

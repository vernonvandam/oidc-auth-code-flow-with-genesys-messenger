
# OIDC Auth Code Flow with Genesys Messenger

A reference implementation demonstrating how to integrate **OpenID Connect (OIDC) Authorization Code Flow** authentication with a **Genesys Web Messenger** deployment.

This sample application provides frontend and service components that handle the OIDC Authorization Code flow, enabling authenticated users to access a Genesys Messenger embed using tokens obtained from an identity provider.

Authenticated web messaging enhances security by ensuring only logged-in users can initiate messaging sessions. Genesys Cloud supports authenticated web messaging via OIDC integrations and uses standard OAuth2 authorization code flows to fetch identity and access tokens.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Features](#features)
3. [Prerequisites](#prerequisites)
4. [Installation](#installation)
5. [Running Locally](#running-locally)
6. [How It Works](#how-it-works)
7. [Troubleshooting & Notes](#troubleshooting--notes)

---

## Project Overview

This repository illustrates a complete flow for:

- Initiating an **OIDC Authorization Code request** from a client application.
- Redirecting the browser to authenticate at an external identity provider.
- Handling the redirect and exchanging the authorization code for tokens.
- Using the authenticated session to embed a **Genesys Web Messenger** with an authenticated user context.

This enables secure web messaging where delegates can engage with visitors only after authentication, aligning with Genesys requirements for secure OIDC integration.

---

## Features

- OIDC Authorization Code flow handling (frontend + backend).
- Token storage and session management.
- Genesys Web Messenger embed with authentication state.
- Utility methods for constructing OIDC URLs and token exchange handlers.

---

## Prerequisites

Before running the project, ensure you have:

- **Node.js** (>= v16 recommended)
- **npm / pnpm** as your package manager
- A configured **OpenID Connect provider** (e.g., Okta, Auth0, Keycloak)
- A registered OAuth2 OIDC client with:
  - **Client ID** and **Client Secret**
  - **Redirect URI** enabled (redirect URL where this app listens)
- A Genesys Cloud tenant setup with:
  - *OpenID Connect Messenger Configuration* enabled in the integrations
  - Authenticated web messaging enabled on the Messenger deployment 

----------

## Installation

Install project dependencies:

`pnpm install` 

(or `npm install` if not using pnpm)

(or `npm install` if not using pnpm)

----------

## Running Locally

Start the local development server:

`pnpm run dev` 

This should host the app (usually at `http://localhost:3000`). Visit it in your browser to begin the authentication flow.

----------

## How It Works

1.  **Initiate Auth Flow**  
    The frontend triggers a redirect to the identity provider’s `/authorize` endpoint with appropriate OIDC parameters (`response_type=code`, `client_id`, `scope`, `redirect_uri`).
    
2.  **User Authenticates**  
    The user authenticates at the identity provider and consents to scopes.
    
3.  **Callback Handling**  
    The identity provider sends the user back to the specified `redirect_uri` with an authorization code.
    
4.  **Token Exchange**  
    The backend service receives the code and exchanges it at the OIDC `/token` endpoint to receive tokens (ID token, access token).
    
5.  **Authenticated Messenger**  
    Tokens are stored in the session and used to render the Genesys Web Messenger component authenticated for the signed-in user.
    

The Authorization Code Grant is the recommended flow for secure interactive applications and enables confidential clients to authenticate securely and maintain tokens server-side.

----------

## Troubleshooting & Notes

-   Ensure your **redirect URI** exactly matches what you registered with the identity provider.
    
-   If your Genesys Messenger fails to authenticate, verify that the _OpenID Connect Messenger Configuration_ integration is correctly configured in your Genesys Cloud tenant.
    
-   OIDC tokens returned to the application may need validation of issuer, audience, and signature according to best practices.
    
-   Token expiration and refresh strategy should be implemented for production systems.
    


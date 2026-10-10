# Independent P2P Crypto Marketplace

A new peer-to-peer crypto marketplace inspired by the usability and workflow of leading P2P platforms. This is an independent product and must not use Binance branding, logos, proprietary assets, or imply affiliation.

## Project principles

- The GitHub repository `akalema-dotcom/P2P` is the source of truth.
- Build and verify backend security before enabling real-money trading.
- Never store private keys, passwords, or service-role secrets in frontend code or Git.
- Never mark a trade as paid or release assets based only on a client-side action.
- Use auditable, atomic server-side operations for order and balance changes.
- Start with sandbox/demo trading until custody, payments, compliance, and security have been reviewed.

## Suggested architecture

- **Frontend:** React + TypeScript + Vite
- **Backend/data:** Supabase Auth, PostgreSQL, Row Level Security, Edge Functions, and Realtime
- **Testing:** unit tests, integration tests, authorization/RLS tests, and concurrent-order tests
- **Deployment:** environment-based configuration; secrets configured in the hosting provider, never committed

## Core modules

1. Authentication, profiles, verification status, and roles
2. Assets, supported fiat currencies, payment methods, and market configuration
3. P2P advertisements with price, limits, available quantity, and seller eligibility
4. Trade orders with server-enforced state transitions and atomic reservations
5. Trade chat and private evidence attachments
6. Payment instructions and payment-status workflow
7. Disputes, moderation, and immutable audit events
8. Fees, notifications, reviews, and reporting
9. Admin tools protected by server-side authorization and database policies

## Trade lifecycle

`created → awaiting_payment → payment_marked → releasing → completed`

Exceptional states must be handled explicitly: `cancelled`, `expired`, and `disputed`. State transitions must be validated server-side. Only an authorized, verified release operation may move a trade to `completed`.

## Build phases

1. Inspect requirements and establish project structure.
2. Configure Supabase and implement database schema, constraints, and RLS.
3. Implement and test secure server-side trade functions.
4. Build marketplace and order interfaces against real backend functions.
5. Add chat, disputes, admin workflows, audit logs, and notifications.
6. Run security, concurrency, integration, and deployment checks.
7. Launch only after legal/compliance and custody/payment design are validated.

## Development status

The repository was initially empty when this README was added. No production-ready exchange or escrow functionality is implied by this planning document.

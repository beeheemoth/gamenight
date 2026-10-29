# Game site + web proxy (password protected)

- `public/`    your game site (static files). Put games in `public/games/`.
- `server.js`  serves the site, the Ultraviolet web proxy, and the password gate.
- `Caddyfile`  reverse proxy that adds HTTPS in front of the Node app.
- `.env`       holds your password (you create this, see below).

## First-time setup
1. Copy `.env.example` to a new file named `.env` and put your own password in it:
       SITE_PASSWORD=something-long-that-you-made-up
2. Run:
       npm install
       npm start
3. Open http://localhost:8080 - you'll get a password page first.

## Changing the password
Edit `.env`, then stop the server (Ctrl+C) and run `npm start` again.
Everyone gets logged out and needs the new password.

## Put it online (VPS)
1. Point your domain's DNS at the server.
2. Edit the domain in `Caddyfile`, then run `caddy run` (install Caddy first).
3. Keep Node alive with pm2: `npm i -g pm2 && pm2 start server.js --name gamesite`

## Notes
- The web proxy needs HTTPS (or localhost) because it uses a service worker.
- Netlify/Vercel/GitHub Pages can't run it: you need a server (VPS, Render, Railway, Fly.io).
- Wisp blocks private/loopback IPs so the proxy can't reach your internal network.
- Logins last 30 days per device. After 10 wrong tries an IP is locked out for 15 minutes.
- Never share your .env file or put it in a public repo.
- Use it where allowed. School and work networks often prohibit proxies.

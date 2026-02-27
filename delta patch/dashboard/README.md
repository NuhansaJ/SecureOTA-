# OTA Dashboard

React dashboard for the OTA update server. Use it from any device on the network.

## Develop

```bash
cd dashboard
npm install
npm run dev
```

Open http://localhost:3000. Vite proxies API requests to the server at port 8000 (start the server separately).

## Build and serve from server

```bash
cd dashboard
npm install
npm run build
```

Then start the server from the project root:

```bash
python -m uvicorn server:app --host 0.0.0.0 --port 8000
```

Open http://YOUR_SERVER_IP:8000 (redirects to /dashboard/) from any device (phone, tablet, desktop) on the same network.

## Features

- View registered devices and their current version / pending update
- List firmware versions and delta patches (REM-encrypted)
- Upload new firmware (.bin)
- Create delta patch (old version → new version; generates REM patch + signature)
- Distribute patch: queue an update for a device (device ID, from version, to version)
- Auto-refresh every 8 seconds

# Frontend

React dashboard for the Network Anomaly Detection System.

## Stack

- React 18
- Vite 6
- Tailwind CSS 3
- Recharts (traffic + detection visualizations)
- Lucide React (icons)

## Development

```bash
npm install
npm run dev
```

The dev server proxies `/api` requests to `http://localhost:8000`.

## Production build

```bash
npm run build
```

Output goes to `dist/`. Serve with any static file server; see `./nginx.conf` and `Dockerfile` for the containerized deployment.
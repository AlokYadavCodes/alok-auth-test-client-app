import 'dotenv/config';

import cookieParser from 'cookie-parser';
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';

import oidcRoutes from './routes/oidc.routes.js';
import userRoutes from './routes/user.routes.js';
import { APP_BASE_URL, OIDC_ISSUER, PORT } from './utils/config.js';
import { clearAuthCookies, readAuthenticatedUser } from './utils/user.utils.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const publicDir = path.resolve(__dirname, '../public');

const app = express();

app.use(express.json());
app.use(cookieParser());

app.get('/', (req, res) => {
  const query = req.originalUrl.includes('?') ? req.originalUrl.slice(req.originalUrl.indexOf('?')) : '';

  try {
    const user = readAuthenticatedUser(req);
    if (!user) {
      return res.redirect(`/welcome${query}`);
    }

    return res.sendFile(path.join(publicDir, 'index.html'));
  } catch (error) {
    clearAuthCookies(res);
    return res.redirect(`/welcome${query}`);
  }
});

app.get('/welcome', (req, res) => {
  res.sendFile(path.join(publicDir, 'welcome.html'));
});

app.use(express.static(publicDir, { index: false }));

app.use(oidcRoutes);
app.use(userRoutes);

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'internal_server_error' });
});

app.listen(PORT, () => {
  console.log(`Server running at ${APP_BASE_URL}`);
  console.log(`OIDC issuer: ${OIDC_ISSUER}`);
});

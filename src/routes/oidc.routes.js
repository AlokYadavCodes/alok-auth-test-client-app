import { Router } from 'express';

import {
  getAuthConfig,
  handleOidcCallback,
  loginWithOidc,
} from '../controllers/oidc.controller.js';

const router = Router();

router.get('/api/auth/config', getAuthConfig);
router.get('/auth/login', loginWithOidc);
router.get('/auth/callback', handleOidcCallback);

export default router;

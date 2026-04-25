import { Router } from 'express';

import { getCurrentUser, logoutUser } from '../controllers/user.controller.js';

const router = Router();

router.get('/api/me', getCurrentUser);
router.post('/auth/logout', logoutUser);

export default router;

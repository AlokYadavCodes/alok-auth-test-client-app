import { OIDC_FLOW_COOKIE, OIDC_ISSUER } from '../utils/config.js';
import {
  clearAuthCookies,
  clearCookie,
  buildUserProfile,
  issueUserSessionToken,
  setUserSessionCookie,
} from '../utils/user.utils.js';
import {
  createAuthorizationRedirectUrl,
  exchangeAuthorizationCode,
  getOidcDiscovery,
  getOidcProviderLabel,
  verifyOidcFlowCookie,
  verifyOidcIdToken,
} from '../utils/oidc.utils.js';

export async function getAuthConfig(req, res) {
  try {
    const discovery = await getOidcDiscovery();

    return res.json({
      issuer: discovery.issuer || OIDC_ISSUER,
      providerLabel: getOidcProviderLabel(discovery),
    });
  } catch (error) {
    console.error('Failed to load OIDC provider config:', error);
    return res.status(500).json({ error: 'provider_config_unavailable' });
  }
}

export async function loginWithOidc(req, res) {
  try {
    const discovery = await getOidcDiscovery();
    const authorizeUrl = createAuthorizationRedirectUrl(res, discovery);
    return res.redirect(authorizeUrl);
  } catch (error) {
    console.error('OIDC login initialization failed:', error);
    clearCookie(res, OIDC_FLOW_COOKIE);
    return res.redirect('/?error=provider_config_unavailable');
  }
}

export async function handleOidcCallback(req, res) {
  const { code, state, error } = req.query;

  if (error) {
    clearCookie(res, OIDC_FLOW_COOKIE);
    return res.redirect('/?error=login_failed');
  }

  if (!code || !state) {
    clearCookie(res, OIDC_FLOW_COOKIE);
    return res.redirect('/?error=missing_callback_params');
  }

  try {
    const flowToken = req.cookies[OIDC_FLOW_COOKIE];
    if (!flowToken) {
      throw new Error('Missing OIDC flow cookie');
    }

    const flow = verifyOidcFlowCookie(flowToken);
    if (flow.state !== state) {
      throw new Error('Invalid OIDC state');
    }

    const discovery = await getOidcDiscovery();
    const tokenPayload = await exchangeAuthorizationCode(code, flow.codeVerifier, discovery);
    const oidcClaims = await verifyOidcIdToken(tokenPayload.id_token, flow.nonce, discovery);
    const user = buildUserProfile(oidcClaims);
    const sessionToken = issueUserSessionToken(user);

    setUserSessionCookie(res, sessionToken);
    clearCookie(res, OIDC_FLOW_COOKIE);

    return res.redirect('/');
  } catch (error) {
    console.error('OIDC callback failed:', error);
    clearAuthCookies(res);
    return res.redirect('/?error=server_error');
  }
}

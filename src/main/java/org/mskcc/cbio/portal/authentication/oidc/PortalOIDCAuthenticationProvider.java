package org.mskcc.cbio.portal.authentication.oidc;

import java.util.ArrayList;
import java.util.Collection;

import org.mitre.openid.connect.client.OIDCAuthenticationProvider;
import org.mitre.openid.connect.model.OIDCAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PortalOIDCAuthenticationProvider extends OIDCAuthenticationProvider {

	private static final Logger log = LoggerFactory.getLogger(PortalOIDCAuthenticationProvider.class);
	
	private PortalOIDCAuthoritiesMapper authoritiesMapper;

	public PortalOIDCAuthoritiesMapper getAuthoritiesMapper() {
		return authoritiesMapper;
	}

	public void setAuthoritiesMapper(PortalOIDCAuthoritiesMapper authoritiesMapper) {
		this.authoritiesMapper = authoritiesMapper;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		Authentication result = super.authenticate(authentication);

		if (result instanceof OIDCAuthenticationToken && result.isAuthenticated()) {

			OIDCAuthenticationToken token = (OIDCAuthenticationToken) result;
			log.info("Logged in as: {}", token);
			log.info("Returned userInfo: {}", token.getUserInfo().toJson().toString());

			String username = token.getUserInfo().getEmail();
			if (username == null || username.length() == 0) 
				username = token.getUserInfo().getPreferredUsername();
			if (username == null || username.length() == 0)
				username = token.getUserInfo().getSub();
			log.info("Identity for permissions: {}", username);

			Collection<GrantedAuthority> portalAuthorities = new ArrayList<GrantedAuthority>();

			portalAuthorities = authoritiesMapper.getPortalAuthorities(username);

			return new OIDCAuthenticationTokenByUsername(username, 
					token.getSub(),
					token.getIssuer(),
					token.getUserInfo(), 
					portalAuthorities, 
					token.getIdToken(),
					token.getAccessTokenValue(), 
					token.getRefreshTokenValue());
		} else {
			return result;
		}

	}
}

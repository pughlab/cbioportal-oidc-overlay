package org.mskcc.cbio.portal.authentication.oidc;

import java.util.Collection;

import org.mitre.openid.connect.model.OIDCAuthenticationToken;
import org.mitre.openid.connect.model.UserInfo;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.nimbusds.jwt.JWT;

public class OIDCAuthenticationTokenByUsername extends OIDCAuthenticationToken {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = -7291083521309931541L;

	protected String username = null;

	
	/**
	 * A modified getPrincipal that returns a UserDetails, even if it's a very stubbed one. This is
	 * needed to handle the cBioPortal assumption that the principal of an Authentication can always
	 * be coerced to a UserDetails with a username. 
	 */
	@Override
	public UserDetails getPrincipal() {
		return new OIDCUserDetails(this);
	}

	public OIDCAuthenticationTokenByUsername(String username, String subject, String issuer, UserInfo userInfo,
			Collection<? extends GrantedAuthority> authorities, JWT idToken, String accessTokenValue,
			String refreshTokenValue) {
		super(subject, issuer, userInfo, authorities, idToken, accessTokenValue, refreshTokenValue);
		this.username = username;
	}
}

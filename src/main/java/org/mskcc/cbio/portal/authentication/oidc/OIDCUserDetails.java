package org.mskcc.cbio.portal.authentication.oidc;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * A slightly modified UserDetails which basically shadows an
 * OIDCAuthenticationTokenByUsername, and returns all its fields 
 * from there. Only getUsername is really needed for cBioPortal, 
 * right now, but other fields might differ when token authenication
 * is better established. 
 * 
 * @author stuart
 *
 */
public class OIDCUserDetails implements UserDetails {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 5739581768712026031L;
	
	private OIDCAuthenticationTokenByUsername token = null;

	public OIDCUserDetails(OIDCAuthenticationTokenByUsername token) {
		super();
		this.token = token;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return token.getAuthorities();
	}

	@Override
	public String getPassword() {
		return null;
	}

	@Override
	public String getUsername() {
		return token.username;
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}

}

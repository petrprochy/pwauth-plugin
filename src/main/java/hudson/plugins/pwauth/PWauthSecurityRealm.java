package hudson.plugins.pwauth;

import com.google.common.base.Function;
import com.google.common.collect.Collections2;
import hudson.Extension;
import hudson.Functions;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.GroupDetails;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.userdetails.User;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.kohsuke.stapler.DataBoundConstructor;
import org.springframework.dao.DataAccessException;

import javax.servlet.Filter;
import javax.servlet.FilterConfig;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;


/** 
 * TODO Replace String Messages with Property Messages<br />
 * TODO additional to white list, support username:password@host URL-Authentication in {@link PWauthFilter}<br />
 * TODO allow host names in white list<br />
 * @author mallox
 *
 */
public class PWauthSecurityRealm extends AbstractPasswordBasedSecurityRealm {
	public final String pwauthPath;
	public final String whitelist;
	public final boolean enableParamAuth;
	public final String idPath;
	public final String groupsPath;
	public final String catPath;
	public final String grepPath;
	
	@DataBoundConstructor
	public PWauthSecurityRealm(final String pwauthPath, final String whitelist, final boolean enableParamAuth, final String idPath, final String groupsPath,
		final String catPath, final String grepPath) {
		this.pwauthPath = pwauthPath;
		this.whitelist = whitelist;
		this.enableParamAuth = enableParamAuth;
		this.grepPath = grepPath;
		this.catPath = catPath;
		this.groupsPath = groupsPath;
		this.idPath = idPath;
		if (PWauthValidation.validatePath(pwauthPath))
			PWauthUtils.setPwAuthPath(pwauthPath);
		if (PWauthValidation.validatePath(grepPath))
			PWauthUtils.setGrepPath(grepPath);
		if (PWauthValidation.validatePath(catPath))
			PWauthUtils.setCatPath(catPath);
		if (PWauthValidation.validatePath(groupsPath))
			PWauthUtils.setGroupsPath(groupsPath);
		if (PWauthValidation.validatePath(idPath))
			PWauthUtils.setIdPath(idPath);
	}

	@Override
	public UserDetails authenticate(String username, String password) throws AuthenticationException {
		try {
			if (PWauthUtils.isUserValid(username, password))
				return new User(username, "", true, true, true, true,
						toAuthorities(username));
		} catch (Exception e) {
			throw new BadCredentialsException("User could not be authenticated", e);
		}
		return null;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
		try {
			if (PWauthUtils.userExists(username))
				return new User(username, "", true, true, true, true,
						toAuthorities(username));
		} catch (IOException ignored) {}
		throw new UsernameNotFoundException("No such Unix user: " + username);
	}

	@Override
	public GroupDetails loadGroupByGroupname(final String groupname) throws UsernameNotFoundException, DataAccessException {
		if (PWauthUtils.groupExists(groupname))
			throw new UsernameNotFoundException(groupname);
		return new GroupDetails() {
			@Override
			public String getName() {
				return groupname;
			}
		};
	}

	@Override
	public Filter createFilter(FilterConfig filterConfig) {
		return new PWauthFilter(super.createFilter(filterConfig), this);
	}

	private static GrantedAuthority[] toAuthorities(String userName) throws IOException {
		final List<String> userGroups = PWauthUtils.getUserGroups(userName);
		final List<GrantedAuthority> authorities = new ArrayList<>(userGroups.size() + 1);
		//noinspection ConstantConditions
		authorities.addAll(Collections2.transform(
				userGroups, (Function<String, GrantedAuthority>) GrantedAuthorityImpl::new));
		authorities.add(AUTHENTICATED_AUTHORITY);
		return authorities.toArray(new GrantedAuthority[0]);
	}

	@SuppressWarnings("unused")
	@Extension
	public static PWauthDescriptor install() {
		if (!Functions.isWindows()) return new PWauthDescriptor();
		return null;
	}
}

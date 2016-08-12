package com.googlecode.fascinator.authentication;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.json.simple.JSONArray;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import com.googlecode.fascinator.api.PluginDescription;
import com.googlecode.fascinator.api.PluginException;
import com.googlecode.fascinator.api.authentication.Authentication;
import com.googlecode.fascinator.api.authentication.AuthenticationException;
import com.googlecode.fascinator.api.authentication.User;
import com.googlecode.fascinator.common.JsonObject;
import com.googlecode.fascinator.common.JsonSimple;
import com.googlecode.fascinator.common.JsonSimpleConfig;
import com.googlecode.fascinator.common.authentication.GenericUser;

import groovy.lang.GroovyClassLoader;
import groovy.lang.GroovyObject;

public class ScriptingAuthentication implements Authentication {

	private JsonSimpleConfig config;
	private final GroovyClassLoader classLoader = new GroovyClassLoader();
	private List<GroovyObject> groovyAuthenticators = new ArrayList<GroovyObject>();

	@Override
	public String getId() {
		return "scripting";
	}

	@Override
	public String getName() {
		return "Scripting Authentication";
	}

	@Override
	public PluginDescription getPluginDetails() {
		return new PluginDescription(this);
	}

	@Override
	public void init(File jsonFile) throws PluginException {
		try {
			this.config = new JsonSimpleConfig(jsonFile);
			initialiseAuthenticators();
		} catch (IOException e) {
			throw new PluginException(e);
		}
	}

	private void initialiseAuthenticators() throws PluginException {
		JSONArray authenticators = config.getArray("authentication", "scripting", "authenticators");

		for (Object object : authenticators) {
			JsonSimple authenticator = new JsonSimple((JsonObject) object);
			String authenticatorId = authenticator.getString(null,"id");
			String scriptType = authenticator.getString(null,"scriptType");
			String scriptPath = authenticator.getString(null,"scriptPath");
			if (scriptPath == null) {
				throw new PluginException("Please specify a scriptPath for the authenticator: " + authenticatorId);
			}
			if (scriptType == null) {
				throw new PluginException("Please specify a scriptType for the authenticator: " + authenticatorId);
			}
			if ("groovy".equals(scriptType)) {
				try {
					Class groovyClass = classLoader.parseClass(new File(scriptPath));
					GroovyObject groovyObj = (GroovyObject) groovyClass.newInstance();
					groovyObj.invokeMethod("init", new Object[] { authenticator.toString() });
					this.groovyAuthenticators.add(groovyObj);
				} catch (Exception e) {
					throw new PluginException(e);
				}

			}
		}

	}

	@Override
	public void init(String jsonString) throws PluginException {
		try {
			this.config = new JsonSimpleConfig(jsonString);
			initialiseAuthenticators();
		} catch (IOException e) {
			throw new PluginException(e);
		}

	}

	@Override
	public void shutdown() throws PluginException {
		// TODO Auto-generated method stub

	}

	@Override
	public User logIn(String username, String password) throws AuthenticationException {
		for (GroovyObject groovyObject : groovyAuthenticators) {
			try {
				User user = (User) groovyObject.invokeMethod("logIn", new Object[] { username, password });
				if (user != null) {
					org.springframework.security.core.Authentication authentication = SecurityContextHolder.getContext()
							.getAuthentication();
					GenericUser details = (GenericUser) authentication.getDetails();
					details.set("scriptingId", (String)groovyObject.invokeMethod("getId", null));
					PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken(
							authentication.getPrincipal(), authentication.getCredentials(),
							authentication.getAuthorities());
					token.setDetails(details);
					SecurityContextHolder.getContext().setAuthentication(token);
				}
				return user;
			} catch (Exception e) {
				// ignore AuthenticationExceptions as they're expected when
				// credentials are incorrect
				if (!(e instanceof AuthenticationException) || !(e instanceof NoSuchMethodException)) {
					throw new AuthenticationException(e);
				}
			}
		}

		throw new AuthenticationException("Username or password invalid");
	}

	@Override
	public void logOut(User user) throws AuthenticationException {
		for (GroovyObject groovyObject : groovyAuthenticators) {
			groovyObject.invokeMethod("logOut", new Object[] { user });
		}
	}

	@Override
	public boolean supportsUserManagement() {
		return false;
	}

	@Override
	public String describeUser() {
		// Not currently used anywhere
		return null;
	}

	@Override
	public User createUser(String username, String password) throws AuthenticationException {
		for (GroovyObject groovyObject : groovyAuthenticators) {
			try {
				return (User) groovyObject.invokeMethod("createUser", new Object[] { username, password });
			} catch (Exception e) {
				// ignore AuthenticationExceptions as they're expected when a
				// script can't create a user
				if (!(e instanceof AuthenticationException) || !(e instanceof NoSuchMethodException)) {
					throw new AuthenticationException(e);
				}
			}
		}
		throw new AuthenticationException("No scripts are able to create a User");
	}

	@Override
	public void deleteUser(String username) throws AuthenticationException {
		for (GroovyObject groovyObject : groovyAuthenticators) {
			try {
				groovyObject.invokeMethod("deleteUser", new Object[] { username });
			} catch (Exception e) {
				// ignore AuthenticationExceptions as they're expected when a
				// script can't delete a user
				if (!(e instanceof AuthenticationException) || !(e instanceof NoSuchMethodException)) {
					throw new AuthenticationException(e);
				}
			}
		}
		throw new AuthenticationException("No scripts are able to delete a User");

	}

	@Override
	public void changePassword(String username, String password) throws AuthenticationException {
		for (GroovyObject groovyObject : groovyAuthenticators) {
			try {
				groovyObject.invokeMethod("changePassword", new Object[] { username, password });
			} catch (Exception e) {
				// ignore AuthenticationExceptions as they're expected when a
				// script can't modify a user
				if (!(e instanceof AuthenticationException) || !(e instanceof NoSuchMethodException)) {
					throw new AuthenticationException(e);
				}
			}
		}
		throw new AuthenticationException("No scripts are able to create a change a user's password");

	}

	@Override
	public User modifyUser(String username, String property, String newValue) throws AuthenticationException {
		for (GroovyObject groovyObject : groovyAuthenticators) {
			try {
				return (User) groovyObject.invokeMethod("modifyUser", new Object[] { username, property, newValue });
			} catch (Exception e) {
				// ignore AuthenticationExceptions as they're expected when a
				// script can't modify a user
				if (!(e instanceof AuthenticationException) || !(e instanceof NoSuchMethodException)) {
					throw new AuthenticationException(e);
				}
			}
		}
		throw new AuthenticationException("No scripts are able to modify a user");
	}

	@Override
	public User modifyUser(String username, String property, int newValue) throws AuthenticationException {
		for (GroovyObject groovyObject : groovyAuthenticators) {
			try {
				return (User) groovyObject.invokeMethod("modifyUser", new Object[] { username, property, newValue });
			} catch (Exception e) {
				// ignore AuthenticationExceptions as they're expected when a
				// script can't modify a user
				if (!(e instanceof AuthenticationException) || !(e instanceof NoSuchMethodException)) {
					throw new AuthenticationException(e);
				}
			}
		}
		throw new AuthenticationException("No scripts are able to modify a user");
	}

	@Override
	public User modifyUser(String username, String property, boolean newValue) throws AuthenticationException {
		for (GroovyObject groovyObject : groovyAuthenticators) {
			try {
				return (User) groovyObject.invokeMethod("modifyUser", new Object[] { username, property, newValue });
			} catch (Exception e) {
				// ignore AuthenticationExceptions as they're expected when a
				// script can't modify a user
				if (!(e instanceof AuthenticationException) || !(e instanceof NoSuchMethodException)) {
					throw new AuthenticationException(e);
				}
			}
		}
		throw new AuthenticationException("No scripts are able to modify a user");
	}

	@Override
	public User getUser(String username) throws AuthenticationException {
		String scriptId = getScriptIdFromAuthenticationToken();
		for (GroovyObject groovyObject : groovyAuthenticators) {
			try {
				if (scriptId != null) {
					if (groovyObject.invokeMethod("getId", null) == scriptId) {
						return (User) groovyObject.invokeMethod("getUser", new Object[] { username });
					}
				} else {
					return (User) groovyObject.invokeMethod("getUser", new Object[] { username });
				}

			} catch (Exception e) {
				// ignore AuthenticationExceptions as they're expected when a
				// script can't get a user
				if (!(e instanceof AuthenticationException) || !(e instanceof NoSuchMethodException)) {
					throw new AuthenticationException(e);
				}
			}
		}
		throw new AuthenticationException("No scripts are able to get the User");
	}

	@Override
	public List<User> searchUsers(String search) throws AuthenticationException {
		for (GroovyObject groovyObject : groovyAuthenticators) {
			try {
				return (List<User>) groovyObject.invokeMethod("searchUsers", new Object[] { search });
			} catch (Exception e) {
				// ignore AuthenticationExceptions as they're expected when a
				// script can't get a user
				if (!(e instanceof AuthenticationException) || !(e instanceof NoSuchMethodException)) {
					throw new AuthenticationException(e);
				}
			}
		}
		throw new AuthenticationException("No scripts are able to get the User");
	}

	private String getScriptIdFromAuthenticationToken() {
		org.springframework.security.core.Authentication authentication = SecurityContextHolder.getContext()
				.getAuthentication();
		GenericUser details = (GenericUser) authentication.getCredentials();
		if (details != null) {
			return details.get("scriptingId");
		}
		return null;
	}
}

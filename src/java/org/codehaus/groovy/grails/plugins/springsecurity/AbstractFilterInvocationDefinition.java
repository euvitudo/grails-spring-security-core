/* Copyright 2006-2010 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.codehaus.groovy.grails.plugins.springsecurity;

import grails.util.GrailsUtil;

import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.expression.Expression;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.AntPathRequestMatcher;
import org.springframework.security.web.util.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public abstract class AbstractFilterInvocationDefinition
       implements FilterInvocationSecurityMetadataSource, InitializingBean {

	private boolean _rejectIfNoRule;
	private Class<? extends RequestMatcher> _requestMatcherClass;
	private RoleVoter _roleVoter;
	private AuthenticatedVoter _authenticatedVoter;
	private SecurityExpressionHandler<FilterInvocation> _expressionHandler;

	private final Map<RequestMatcher, Collection<ConfigAttribute>> _compiled = new LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>>();

	protected final static Logger _log = Logger.getLogger(AbstractFilterInvocationDefinition.class);

	protected static final Collection<ConfigAttribute> DENY = Collections.emptyList();
	
	/**
	 * Allows subclasses to be externally reset.
	 * @throws Exception
	 */
	public void reset() throws Exception {
		// override if necessary
	}

	/**
	 * {@inheritDoc}
	 * @see org.springframework.security.access.SecurityMetadataSource#getAttributes(java.lang.Object)
	 */
	public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
		Assert.isTrue(object != null && supports(object.getClass()), "Object must be a FilterInvocation");

		FilterInvocation filterInvocation = (FilterInvocation)object;

		Collection<ConfigAttribute> configAttributes;
		try {
			configAttributes = findConfigAttributes(filterInvocation.getHttpRequest());
		}
		catch (Exception e) {
			// TODO fix this
			throw new RuntimeException(e);
		}

		if (configAttributes == null && _rejectIfNoRule) {
			return DENY;
		}

		return configAttributes;
	}

	protected boolean stopAtFirstMatch() {
		return false;
	}

	private Collection<ConfigAttribute> findConfigAttributes(final HttpServletRequest request) throws Exception {

		initialize();

		Collection<ConfigAttribute> configAttributes = null;
		RequestMatcher configAttributeRequestMatcher = null;

		boolean stopAtFirstMatch = stopAtFirstMatch();
		for (Map.Entry<RequestMatcher, Collection<ConfigAttribute>> entry : _compiled.entrySet()) {
			RequestMatcher requestMatcher = entry.getKey();
			if (requestMatcher.matches(request)) {
				// TODO this assumes Ant matching, for the most part; not valid for regex
				if (configAttributes == null || (configAttributeRequestMatcher != null &&  configAttributeRequestMatcher.matches(request))) {
					configAttributes = entry.getValue();
					if (requestMatcher instanceof AntPathRequestMatcher) {
						configAttributeRequestMatcher = new AntPathRequestMatcher(AntPathRequestMatcher.class.cast(requestMatcher).getPattern());
					}
					if (_log.isTraceEnabled()) {
						_log.trace("new candidate for '" + request.getRequestURL() + "': '" + requestMatcher
								+ "':" + configAttributes);
					}
					if (stopAtFirstMatch) {
						break;
					}
				}
			}
		}

		if (_log.isTraceEnabled()) {
			if (configAttributes == null) {
				_log.trace("no config for '" + request.getRequestURL() + "'");
			}
			else {
				_log.trace("config for '" + request.getRequestURL() + "' is '" + configAttributeRequestMatcher + "':" + configAttributes);
			}
		}

		return configAttributes;
	}

	protected void initialize() throws Exception {
		// override if necessary
	}

	/**
	 * {@inheritDoc}
	 * @see org.springframework.security.access.SecurityMetadataSource#supports(java.lang.Class)
	 */
	public boolean supports(Class<?> clazz) {
		return FilterInvocation.class.isAssignableFrom(clazz);
	}

	/**
	 * {@inheritDoc}
	 * @see org.springframework.security.access.SecurityMetadataSource#getAllConfigAttributes()
	 */
	public Collection<ConfigAttribute> getAllConfigAttributes() {
		try {
			initialize();
		}
		catch (Exception e) {
			GrailsUtil.deepSanitize(e);
			_log.error(e.getMessage(), e);
		}

		Collection<ConfigAttribute> all = new HashSet<ConfigAttribute>();
		for (Collection<ConfigAttribute> configs : _compiled.values()) {
			all.addAll(configs);
		}
		return Collections.unmodifiableCollection(all);
	}

	/**
	 * Dependency injection for the url matcher.
	 * @param urlMatcher the matcher
	 */
	public void setRequestMatcherClass(final Class<? extends RequestMatcher> requestMatcherClass) {
		_requestMatcherClass = requestMatcherClass;
	}

	/**
	 * Dependency injection for whether to reject if there's no matching rule.
	 * @param reject if true, reject access unless there's a pattern for the specified resource
	 */
	public void setRejectIfNoRule(final boolean reject) {
		_rejectIfNoRule = reject;
	}

	protected Class<? extends RequestMatcher> getRequestMatcherClass() {
		return _requestMatcherClass;
	}

	/**
	 * For debugging.
	 * @return an unmodifiable map of {@link AnnotationFilterInvocationDefinition}ConfigAttributeDefinition
	 * keyed by compiled patterns
	 */
	public Map<RequestMatcher, Collection<ConfigAttribute>> getConfigAttributeMap() {
		return Collections.unmodifiableMap(_compiled);
	}

	// fixes extra spaces, trailing commas, etc.
	protected List<String> split(final String value) {
		if (!value.startsWith("ROLE_") && !value.startsWith("IS_")) {
			// an expression
			return Collections.singletonList(value);
		}

		String[] parts = StringUtils.commaDelimitedListToStringArray(value);
		List<String> cleaned = new ArrayList<String>();
		for (String part : parts) {
			part = part.trim();
			if (part.length() > 0) {
				cleaned.add(part);
			}
		}
		return cleaned;
	}

	protected void compileAndStoreMapping(final String pattern, final List<String> tokens) {

		Collection<ConfigAttribute> configAttributes = buildConfigAttributes(tokens);

		Collection<ConfigAttribute> replaced = storeMapping(pattern,
				Collections.unmodifiableCollection(configAttributes));
		if (replaced != null) {
			_log.warn("replaced rule for '" + pattern + "' with roles " + replaced +
					" with roles " + configAttributes);
		}
	}

	/**
	 * @param clazz
	 * @param pattern
	 * @param object
	 * @return
	 */
	public static RequestMatcher resolveRequestMatcher(Class<? extends RequestMatcher> clazz, String pattern) {
		RequestMatcher key = null;
		Constructor<? extends RequestMatcher> constructor = null;
		// we know it's one of these two
		try {
			constructor = clazz.getConstructor(String.class);
			key = constructor.newInstance(pattern);
		} catch (Exception e) {
			_log.error(e);
		}
		try {
			constructor = clazz.getConstructor(String.class, String.class);
			key = constructor.newInstance(pattern, null);
		} catch (Exception e) {
			_log.error(e);
		}
		if (key == null) {
			throw new RuntimeException("cannot instantiate type: " + clazz);
		}
		return key;
	}

	protected Collection<ConfigAttribute> buildConfigAttributes(final Collection<String> tokens) {
		Collection<ConfigAttribute> configAttributes = new HashSet<ConfigAttribute>();
		for (String token : tokens) {
			ConfigAttribute config = new SecurityConfig(token);
			if (supports(config)) {
				configAttributes.add(config);
			}
			else {
				Expression expression = _expressionHandler.getExpressionParser().parseExpression(token);
				configAttributes.add(new WebExpressionConfigAttribute(expression));
			}
		}
		return configAttributes;
	}

	protected boolean supports(final ConfigAttribute config) {
		return supports(config, _roleVoter) || supports(config, _authenticatedVoter) ||
				config.getAttribute().startsWith("RUN_AS");
	}

	private boolean supports(final ConfigAttribute config, final AccessDecisionVoter voter) {
		return voter != null && voter.supports(config);
	}

	protected Collection<ConfigAttribute> storeMapping(final String pattern,
			final Collection<ConfigAttribute> configAttributes) {
		RequestMatcher key = resolveRequestMatcher(getRequestMatcherClass(), pattern);
		return _compiled.put(key, configAttributes);
	}

	protected void resetConfigs() {
		_compiled.clear();
	}

	/**
	 * TODO: FIX!
	 * For admin/debugging - find all config attributes that apply to the specified URL.
	 * @param url the URL
	 * @return matching attributes
	 */
	public Collection<ConfigAttribute> findMatchingAttributes(final RequestMatcher matcher) {
		for (Map.Entry<RequestMatcher, Collection<ConfigAttribute>> entry : _compiled.entrySet()) {
			if (entry.getKey().equals(matcher)) {
				return entry.getValue();
			}
		}
		return Collections.emptyList();
	}

	/**
	 * Dependency injection for the role voter.
	 * @param voter the voter
	 */
	public void setRoleVoter(final RoleVoter voter) {
		_roleVoter = voter;
	}

	protected RoleVoter getRoleVoter() {
		return _roleVoter;
	}

	/**
	 * Dependency injection for the authenticated voter.
	 * @param voter the voter
	 */
	public void setAuthenticatedVoter(final AuthenticatedVoter voter) {
		_authenticatedVoter = voter;
	}
	protected AuthenticatedVoter getAuthenticatedVoter() {
		return _authenticatedVoter;
	}

	/**
	 * Dependency injection for the expression handler.
	 * @param handler the handler
	 */
	public void setExpressionHandler(final SecurityExpressionHandler<FilterInvocation> handler) {
		_expressionHandler = handler;
	}
	protected SecurityExpressionHandler<FilterInvocation> getExpressionHandler() {
		return _expressionHandler;
	}

	/**
	 * {@inheritDoc}
	 * @see org.springframework.beans.factory.InitializingBean#afterPropertiesSet()
	 */
	public void afterPropertiesSet() {
		Assert.notNull(_requestMatcherClass, "requestMatcherClass is required");
	}
}

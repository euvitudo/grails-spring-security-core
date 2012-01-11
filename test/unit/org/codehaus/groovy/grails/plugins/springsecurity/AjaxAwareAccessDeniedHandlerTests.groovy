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
package org.codehaus.groovy.grails.plugins.springsecurity

import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.authentication.AuthenticationTrustResolverImpl
import org.springframework.security.authentication.RememberMeAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder as SCH
import org.springframework.security.web.PortResolverImpl
import org.springframework.security.web.savedrequest.DefaultSavedRequest
import org.springframework.security.web.savedrequest.HttpSessionRequestCache

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class AjaxAwareAccessDeniedHandlerTests extends GroovyTestCase {

	private final _handler = new AjaxAwareAccessDeniedHandler()
	private final _application = new FakeApplication()
	private final _requestCache = new HttpSessionRequestCache()

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() {
		super.setUp()
		_handler.errorPage = '/fail'
		_handler.ajaxErrorPage = '/ajaxFail'
		_handler.portResolver = new PortResolverImpl()
		_handler.authenticationTrustResolver = new AuthenticationTrustResolverImpl()
		_handler.requestCache = _requestCache
		ReflectionUtils.application = _application
		ReflectionUtils.setConfigProperty 'ajaxHeader', SpringSecurityUtils.AJAX_HEADER
	}

	void testHandleAuthenticatedRememberMe() {
		def request = new MockHttpServletRequest()
		def response = new MockHttpServletResponse()

		SCH.context.authentication = new RememberMeAuthenticationToken('username', 'password', null)

		assertNull _requestCache.getRequest(request, response)
		_handler.handle request, response, new AccessDeniedException('fail')
		assertNotNull _requestCache.getRequest(request, response)

		assertEquals 'http://localhost/fail', response.redirectedUrl
	}

	void testHandleAuthenticatedAjax() {
		def request = new MockHttpServletRequest()
		def response = new MockHttpServletResponse()

		request.addHeader SpringSecurityUtils.AJAX_HEADER, 'XHR'

		_handler.handle request, response, new AccessDeniedException('fail')

		assertEquals 'http://localhost/ajaxFail', response.redirectedUrl
	}

	void testHandleAuthenticatedNotAjax() {
		def request = new MockHttpServletRequest()
		def response = new MockHttpServletResponse()

		_handler.handle request, response, new AccessDeniedException('fail')

		assertEquals 'http://localhost/fail', response.redirectedUrl
	}

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() {
		super.tearDown()
		SCH.context.authentication = null
		ReflectionUtils.application = null
	}
}

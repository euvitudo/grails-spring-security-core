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

import grails.plugins.springsecurity.SecurityConfigType

import org.codehaus.groovy.grails.commons.ApplicationHolder as AH
import org.codehaus.groovy.grails.commons.ConfigurationHolder as CH
import org.springframework.context.ApplicationContext
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.web.PortResolverImpl
import org.springframework.security.web.savedrequest.DefaultSavedRequest
import org.springframework.security.web.savedrequest.HttpSessionRequestCache

/**
 * Unit tests for SpringSecurityUtils.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class SpringSecurityUtilsTests extends GroovyTestCase {

	private final application = new FakeApplication()
	private final requestCache = new HttpSessionRequestCache()

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() {
		super.setUp()
		ReflectionUtils.application = application
	}

	/**
	 * Test authoritiesToRoles().
	 */
	void testAuthoritiesToRoles() {

		def roleNames = []
		def authorities = []
		(1..10).each { i ->
			String name = "role${i}"
			roleNames << name
			authorities << new SimpleGrantedAuthority(name)
		}

		def roles = SpringSecurityUtils.authoritiesToRoles(authorities)
		assertSameContents roleNames, roles
	}

	/**
	 * Test authoritiesToRoles() when there is an authority with a null string.
	 */
	void testAuthoritiesToRolesNullAuthority() {

		def authorities = [new SimpleGrantedAuthority('role1'), new FakeAuthority()]

		shouldFail(IllegalArgumentException) {
			SpringSecurityUtils.authoritiesToRoles(authorities)
		}
	}

	/**
	 * Test getPrincipalAuthorities() when not authenticated.
	 */
	void testGetPrincipalAuthoritiesNoAuth() {
		assertTrue SpringSecurityUtils.getPrincipalAuthorities().empty
	}

	/**
	 * Test getPrincipalAuthorities() when not authenticated.
	 */
	void testGetPrincipalAuthoritiesNoRoles() {
		SecurityTestUtils.authenticate()
		assertTrue SpringSecurityUtils.getPrincipalAuthorities().empty
	}

	/**
	 * Test getPrincipalAuthorities().
	 */
	void testGetPrincipalAuthorities() {
		def authorities = []
		(1..10).each { i ->
			authorities << new SimpleGrantedAuthority("role${i}")
		}

		SecurityTestUtils.authenticate(null, null, authorities)

		assertEquals authorities, SpringSecurityUtils.getPrincipalAuthorities()
	}

	/**
	 * Test parseAuthoritiesString().
	 */
	void testParseAuthoritiesString() {
		String roleNames = 'role1,role2,role3'
		def roles = SpringSecurityUtils.parseAuthoritiesString(roleNames)

		assertEquals 3, roles.size()
		def expected = ['role1', 'role2', 'role3']
		def actual = roles.collect { authority -> authority.authority }
		assertSameContents expected, actual
	}

	/**
	 * Test retainAll().
	 */
	void testRetainAll() {
		def granted = [new SimpleGrantedAuthority('role1'),
		               new SimpleGrantedAuthority('role2'),
		               new SimpleGrantedAuthority('role3')]
		def required = [new SimpleGrantedAuthority('role1')]

		def expected = ['role1']
		assertSameContents expected, SpringSecurityUtils.retainAll(granted, required)
	}

	void testIsAjaxUsingParameterFalse() {
		assertFalse SpringSecurityUtils.isAjax(requestCache, new MockHttpServletRequest(), new MockHttpServletResponse())
	}

	void testIsAjaxUsingParameterTrue() {

		def request = new MockHttpServletRequest()
		request.setParameter('ajax', 'true')

		assertTrue SpringSecurityUtils.isAjax(requestCache, request, new MockHttpServletResponse())
	}

	void testIsAjaxUsingHeaderFalse() {
		assertFalse SpringSecurityUtils.isAjax(requestCache, new MockHttpServletRequest(), new MockHttpServletResponse())
	}

	void testIsAjaxUsingHeaderTrue() {

		def request = new MockHttpServletRequest()
		request.addHeader('X-Requested-With', 'foo')

		assertTrue SpringSecurityUtils.isAjax(requestCache, request, new MockHttpServletResponse())
	}

	void testIsAjaxUsingSavedRequestFalse() {

		def request = new MockHttpServletRequest()
		def response = new MockHttpServletResponse()
//		def savedRequest = new DefaultSavedRequest(request, new PortResolverImpl())
//		request.session.setAttribute(DefaultSavedRequest.SPRING_SECURITY_SAVED_REQUEST_KEY, savedRequest)
		requestCache.saveRequest(request, response)

		assertFalse SpringSecurityUtils.isAjax(requestCache, request, response)
	}

	void testIsAjaxUsingSavedRequestTrue() {

		def request = new MockHttpServletRequest()
		request.addHeader 'X-Requested-With', 'true'
		def response = new MockHttpServletResponse()
//		def savedRequest = new DefaultSavedRequest(request, new PortResolverImpl())
//		request.session.setAttribute(DefaultSavedRequest.SPRING_SECURITY_SAVED_REQUEST_KEY, savedRequest)
		requestCache.saveRequest(request, response)
		
		assertTrue SpringSecurityUtils.isAjax(requestCache, request, response)
	}

	void testIfAllGranted() {
		initRoleHierarchy ''
		SecurityTestUtils.authenticate(['ROLE_1', 'ROLE_2'])

		assertTrue SpringSecurityUtils.ifAllGranted('ROLE_1')
		assertTrue SpringSecurityUtils.ifAllGranted('ROLE_2')
		assertTrue SpringSecurityUtils.ifAllGranted('ROLE_1,ROLE_2')
		assertFalse SpringSecurityUtils.ifAllGranted('ROLE_1,ROLE_2,ROLE_3')
		assertFalse SpringSecurityUtils.ifAllGranted('ROLE_3')
	}

	void testIfAllGranted_UsingHierarchy() {
		initRoleHierarchy 'ROLE_3 > ROLE_2 \n ROLE_2 > ROLE_1'
		SecurityTestUtils.authenticate(['ROLE_3'])

		assertTrue SpringSecurityUtils.ifAllGranted('ROLE_1')
		assertTrue SpringSecurityUtils.ifAllGranted('ROLE_2')
		assertTrue SpringSecurityUtils.ifAllGranted('ROLE_1,ROLE_2')
		assertTrue SpringSecurityUtils.ifAllGranted('ROLE_1,ROLE_2,ROLE_3')
		assertTrue SpringSecurityUtils.ifAllGranted('ROLE_3')
		assertFalse SpringSecurityUtils.ifAllGranted('ROLE_4')
	}

	void testIfNotGranted() {
		initRoleHierarchy ''
		SecurityTestUtils.authenticate(['ROLE_1', 'ROLE_2'])

		assertFalse SpringSecurityUtils.ifNotGranted('ROLE_1')
		assertFalse SpringSecurityUtils.ifNotGranted('ROLE_2')
		assertFalse SpringSecurityUtils.ifNotGranted('ROLE_1,ROLE_2')
		assertFalse SpringSecurityUtils.ifNotGranted('ROLE_1,ROLE_2,ROLE_3')
		assertTrue SpringSecurityUtils.ifNotGranted('ROLE_3')
	}

	void testIfNotGranted_UsingHierarchy() {
		initRoleHierarchy 'ROLE_3 > ROLE_2 \n ROLE_2 > ROLE_1'
		SecurityTestUtils.authenticate(['ROLE_3'])

		assertFalse SpringSecurityUtils.ifNotGranted('ROLE_1')
		assertFalse SpringSecurityUtils.ifNotGranted('ROLE_2')
		assertFalse SpringSecurityUtils.ifNotGranted('ROLE_1,ROLE_2')
		assertFalse SpringSecurityUtils.ifNotGranted('ROLE_1,ROLE_2,ROLE_3')
		assertFalse SpringSecurityUtils.ifNotGranted('ROLE_3')
		assertTrue SpringSecurityUtils.ifNotGranted('ROLE_4')
	}

	void testIfAnyGranted() {
		initRoleHierarchy ''
		SecurityTestUtils.authenticate(['ROLE_1', 'ROLE_2'])

		assertTrue SpringSecurityUtils.ifAnyGranted('ROLE_1')
		assertTrue SpringSecurityUtils.ifAnyGranted('ROLE_2')
		assertTrue SpringSecurityUtils.ifAnyGranted('ROLE_1,ROLE_2')
		assertTrue SpringSecurityUtils.ifAnyGranted('ROLE_1,ROLE_2,ROLE_3')
		assertFalse SpringSecurityUtils.ifAnyGranted('ROLE_3')
	}

	void testIfAnyGranted_UsingHierarchy() {
		initRoleHierarchy 'ROLE_3 > ROLE_2 \n ROLE_2 > ROLE_1'
		SecurityTestUtils.authenticate(['ROLE_3'])

		assertTrue SpringSecurityUtils.ifAnyGranted('ROLE_1')
		assertTrue SpringSecurityUtils.ifAnyGranted('ROLE_2')
		assertTrue SpringSecurityUtils.ifAnyGranted('ROLE_1,ROLE_2')
		assertTrue SpringSecurityUtils.ifAnyGranted('ROLE_1,ROLE_2,ROLE_3')
		assertTrue SpringSecurityUtils.ifAnyGranted('ROLE_3')
		assertFalse SpringSecurityUtils.ifAnyGranted('ROLE_4')
	}

	void testPrivateConstructor() {
		SecurityTestUtils.testPrivateConstructor SpringSecurityUtils
	}

	void testGetSecurityConfigType() {
		application.config.grails.plugins.springsecurity.securityConfigType = SecurityConfigType.Annotation
		assertEquals 'Annotation', SpringSecurityUtils.securityConfigType

		application.config.grails.plugins.springsecurity.securityConfigType = SecurityConfigType.Annotation.name()
		assertEquals 'Annotation', SpringSecurityUtils.securityConfigType

		application.config.grails.plugins.springsecurity.securityConfigType = 'Annotation'
		assertEquals 'Annotation', SpringSecurityUtils.securityConfigType

		application.config.grails.plugins.springsecurity.securityConfigType = SecurityConfigType.InterceptUrlMap
		assertEquals 'InterceptUrlMap', SpringSecurityUtils.securityConfigType

		application.config.grails.plugins.springsecurity.securityConfigType = SecurityConfigType.InterceptUrlMap.name()
		assertEquals 'InterceptUrlMap', SpringSecurityUtils.securityConfigType

		application.config.grails.plugins.springsecurity.securityConfigType = 'InterceptUrlMap'
		assertEquals 'InterceptUrlMap', SpringSecurityUtils.securityConfigType

		application.config.grails.plugins.springsecurity.securityConfigType = SecurityConfigType.Requestmap
		assertEquals 'Requestmap', SpringSecurityUtils.securityConfigType

		application.config.grails.plugins.springsecurity.securityConfigType = SecurityConfigType.Requestmap.name()
		assertEquals 'Requestmap', SpringSecurityUtils.securityConfigType

		application.config.grails.plugins.springsecurity.securityConfigType = 'Requestmap'
		assertEquals 'Requestmap', SpringSecurityUtils.securityConfigType
	}

	/**
	 * Check that two collections contain the same data, independent of collection class and order.
	 */
	private void assertSameContents(c1, c2) {
		assertEquals c1.size(), c2.size()
		assertTrue c1.containsAll(c2)
	}

	private void initRoleHierarchy(String hierarchy) {
		def roleHierarchy = new RoleHierarchyImpl(hierarchy: hierarchy)
		def ctx = [getBean: { String name -> roleHierarchy }] as ApplicationContext
		AH.application = new FakeApplication(mainContext: ctx)
		SpringSecurityUtils.application = AH.application
	}

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() {
		super.tearDown()
		SecurityTestUtils.logout()
		SpringSecurityUtils.resetSecurityConfig()
		AH.application = null
		CH.config = null
		SpringSecurityUtils.application = null
		ReflectionUtils.application = null
	}
}

class FakeAuthority implements GrantedAuthority {
	String authority
}

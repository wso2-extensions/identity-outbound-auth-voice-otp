/*
 *  Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.wso2.carbon.identity.authenticator.voiceotp.test;

import org.apache.commons.lang.StringUtils;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.Spy;
import org.mockito.ArgumentCaptor;
import org.owasp.encoder.Encode;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.extension.identity.helper.FederatedAuthenticatorUtil;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.authenticator.voiceotp.OneTimePasswordUtils;
import org.wso2.carbon.identity.authenticator.voiceotp.VoiceOTPAuthenticator;
import org.wso2.carbon.identity.authenticator.voiceotp.VoiceOTPConstants;
import org.wso2.carbon.identity.authenticator.voiceotp.VoiceOTPUtils;
import org.wso2.carbon.identity.authenticator.voiceotp.internal.VoiceOTPServiceDataHolder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.claim.Claim;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.wso2.carbon.identity.authenticator.voiceotp.VoiceOTPConstants.DIVISOR;
import static org.wso2.carbon.identity.authenticator.voiceotp.VoiceOTPConstants.OTP_SEPARATOR;
import static org.wso2.carbon.identity.authenticator.voiceotp.VoiceOTPConstants.POST_METHOD;
import static org.wso2.carbon.identity.authenticator.voiceotp.VoiceOTPConstants.REQUESTED_USER_MOBILE;

public class VoiceOTPAuthenticatorTest {

    private static final long otpTime = 1608101321322L;

    @Spy
    private AuthenticationContext context;
    @Mock
    private HttpServletRequest httpServletRequest;
    @Mock
    private ConfigurationFacade configurationFacade;
    @Mock
    private HttpServletResponse response;
    @Mock
    private UserStoreManager userStoreManager;
    @Mock
    private UserRealm userRealm;
    @Mock
    private RealmService realmService;
    @Mock
    private ClaimManager claimManager;
    @Mock
    private Claim claim;
    @Mock
    private AuthenticatedUser authenticatedUser;
    @Mock
    private Map<String, String> authenticatorProperties;
    @Mock
    private HttpURLConnection httpURLConnection;
    @InjectMocks
    private VoiceOTPAuthenticator authenticator = new VoiceOTPAuthenticator();

    private AutoCloseable mocks;
    private MockedStatic<MultitenantUtils> mockedMultitenantUtils;
    private MockedStatic<VoiceOTPUtils> mockedVoiceOTPUtils;
    private MockedStatic<OneTimePasswordUtils> mockedOneTimePasswordUtils;
    private MockedStatic<FederatedAuthenticatorUtil> mockedFederatedAuthenticatorUtil;
    private MockedStatic<IdentityTenantUtil> mockedIdentityTenantUtil;
    private MockedStatic<ConfigurationFacade> mockedConfigurationFacade;
    private MockedStatic<FrameworkUtils> mockedFrameworkUtils;
    private MockedStatic<IdentityUtil> mockedIdentityUtil;

    @BeforeMethod
    public void setUp() {
        mocks = MockitoAnnotations.openMocks(this);
        mockedMultitenantUtils = Mockito.mockStatic(MultitenantUtils.class);
        mockedVoiceOTPUtils = Mockito.mockStatic(VoiceOTPUtils.class);
        mockedOneTimePasswordUtils = Mockito.mockStatic(OneTimePasswordUtils.class);
        mockedFederatedAuthenticatorUtil = Mockito.mockStatic(FederatedAuthenticatorUtil.class);
        mockedIdentityTenantUtil = Mockito.mockStatic(IdentityTenantUtil.class);
        mockedConfigurationFacade = Mockito.mockStatic(ConfigurationFacade.class);
        mockedFrameworkUtils = Mockito.mockStatic(FrameworkUtils.class);
        mockedIdentityUtil = Mockito.mockStatic(IdentityUtil.class);
    }

    @AfterMethod
    public void tearDown() throws Exception {
        mockedMultitenantUtils.close();
        mockedVoiceOTPUtils.close();
        mockedOneTimePasswordUtils.close();
        mockedFederatedAuthenticatorUtil.close();
        mockedIdentityTenantUtil.close();
        mockedConfigurationFacade.close();
        mockedFrameworkUtils.close();
        mockedIdentityUtil.close();
        mocks.close();
    }

    @Test
    public void testGetFriendlyName() {
        Assert.assertEquals(authenticator.getFriendlyName(), VoiceOTPConstants.AUTHENTICATOR_FRIENDLY_NAME);
    }

    @Test
    public void testGetName() {
        Assert.assertEquals(authenticator.getName(), VoiceOTPConstants.AUTHENTICATOR_NAME);
    }

    @Test
    public void testRetryAuthenticationEnabled() throws Exception {
        VoiceOTPAuthenticator voiceotp = Mockito.spy(authenticator);
        Assert.assertTrue((Boolean) invokePrivateMethod(voiceotp, "retryAuthenticationEnabled"));
    }

    @Test
    public void testGetContextIdentifierPassed() {
        Mockito.when(httpServletRequest.getParameter(FrameworkConstants.SESSION_DATA_KEY)).thenReturn("0246893");
        Assert.assertEquals(authenticator.getContextIdentifier(httpServletRequest), "0246893");
    }

    @Test
    public void testCanHandleTrue() {
        Mockito.when(httpServletRequest.getParameter(VoiceOTPConstants.CODE)).thenReturn(null);
        Mockito.when(httpServletRequest.getParameter(VoiceOTPConstants.RESEND)).thenReturn("resendCode");
        Assert.assertEquals(authenticator.canHandle(httpServletRequest), true);
    }

    @Test
    public void testCanHandleFalse() {
        Mockito.when(httpServletRequest.getParameter(VoiceOTPConstants.CODE)).thenReturn(null);
        Mockito.when(httpServletRequest.getParameter(VoiceOTPConstants.RESEND)).thenReturn(null);
        Mockito.when(httpServletRequest.getParameter(VoiceOTPConstants.MOBILE_NUMBER)).thenReturn(null);
        Assert.assertEquals(authenticator.canHandle(httpServletRequest), false);
    }

    @Test
    public void testCanHandleWithCode() {
        Mockito.when(httpServletRequest.getParameter(VoiceOTPConstants.CODE)).thenReturn("123456");
        Assert.assertEquals(authenticator.canHandle(httpServletRequest), true);
    }

    @Test
    public void testCanHandleWithMobileNumber() {
        Mockito.when(httpServletRequest.getParameter(VoiceOTPConstants.CODE)).thenReturn(null);
        Mockito.when(httpServletRequest.getParameter(VoiceOTPConstants.RESEND)).thenReturn(null);
        Mockito.when(httpServletRequest.getParameter(VoiceOTPConstants.MOBILE_NUMBER)).thenReturn("0771234567");
        Assert.assertEquals(authenticator.canHandle(httpServletRequest), true);
    }

    @Test
    public void testGetCorrelationId() {
        String correlationId = VoiceOTPAuthenticator.getCorrelationId();
        Assert.assertNotNull(correlationId);

        org.slf4j.MDC.put(VoiceOTPConstants.CORRELATION_ID_MDC, "test-correlation-id");
        try {
            Assert.assertEquals(VoiceOTPAuthenticator.getCorrelationId(), "test-correlation-id");
        } finally {
            org.slf4j.MDC.remove(VoiceOTPConstants.CORRELATION_ID_MDC);
        }
    }

    @Test
    public void testGetURL() throws Exception {
        VoiceOTPAuthenticator voiceotp = Mockito.spy(authenticator);
        Assert.assertEquals(invokePrivateMethod(voiceotp, "getURL",
                new Class[]{String.class, String.class},
                VoiceOTPConstants.LOGIN_PAGE, null),
                "authenticationendpoint/login.do?authenticators=VoiceOTP");
    }

    @Test
    public void testGetURLwithQueryParams() throws Exception {
        VoiceOTPAuthenticator voiceotp = Mockito.spy(authenticator);
        Assert.assertEquals(invokePrivateMethod(voiceotp, "getURL",
                new Class[]{String.class, String.class},
                VoiceOTPConstants.LOGIN_PAGE, "n=John&n=Susan"),
                "authenticationendpoint/login.do?n=John&n=Susan&authenticators=VoiceOTP");
    }

    @Test
    public void testGetMobileNumber() throws Exception {
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getMobileNumberForUsername(anyString())).thenReturn("0775968325");
        Assert.assertEquals(invokePrivateMethod(authenticator, "getMobileNumber",
                new Class[]{HttpServletRequest.class, HttpServletResponse.class,
                        AuthenticationContext.class, String.class, String.class},
                httpServletRequest, response, context, "Kanapriya", "queryParams"), "0775968325");
    }

    @Test
    public void testGetLoginPage() throws Exception {
        mockedConfigurationFacade.when(ConfigurationFacade::getInstance).thenReturn(configurationFacade);
        Mockito.when(configurationFacade.getAuthenticationEndpointURL())
                .thenReturn("/authenticationendpoint/login.do");
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getLoginPageFromXMLFile(any(AuthenticationContext.class)))
                .thenReturn(null);
        Assert.assertNotEquals(invokePrivateMethod(authenticator, "getLoginPage",
                new AuthenticationContext()), "/authenticationendpoint/login.do");
        Assert.assertEquals(invokePrivateMethod(authenticator, "getLoginPage",
                new AuthenticationContext()), "/authenticationendpoint/voiceOtp.jsp");
    }

    @Test
    public void testGetErrorPage() throws Exception {
        mockedConfigurationFacade.when(ConfigurationFacade::getInstance).thenReturn(configurationFacade);
        Mockito.when(configurationFacade.getAuthenticationEndpointURL())
                .thenReturn("/authenticationendpoint/login.do");
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getErrorPageFromXMLFile(any(AuthenticationContext.class)))
                .thenReturn(null);
        Assert.assertNotEquals(invokePrivateMethod(authenticator, "getErrorPage",
                new AuthenticationContext()), "/authenticationendpoint/login.do");
        Assert.assertEquals(invokePrivateMethod(authenticator, "getErrorPage",
                new AuthenticationContext()), "/authenticationendpoint/voiceOtpError.jsp");
    }

    @Test
    public void testRedirectToErrorPage() throws Exception {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getErrorPageFromXMLFile(authenticationContext))
                .thenReturn("/authenticationendpoint/voiceOtpError.jsp");
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        invokePrivateMethod(authenticator, "redirectToErrorPage",
                new Class[]{HttpServletResponse.class, AuthenticationContext.class, String.class, String.class},
                response, authenticationContext, null, null);
        verify(response).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(VoiceOTPConstants.AUTHENTICATOR_NAME));
    }

    @Test
    public void testRedirectToMobileNumberReqPage() throws Exception {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isEnableMobileNoUpdate(authenticationContext)).thenReturn(true);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getMobileNumberRequestPage(authenticationContext))
                .thenReturn("/authenticationendpoint/mobile.jsp");
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        invokePrivateMethod(authenticator, "redirectToMobileNoReqPage",
                new Class[]{HttpServletResponse.class, AuthenticationContext.class, String.class},
                response, authenticationContext, null);
        verify(response).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(VoiceOTPConstants.AUTHENTICATOR_NAME));
    }

    @Test
    public void testCheckStatusCode() throws Exception {
        context.setProperty(VoiceOTPConstants.STATUS_CODE, "");
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isRetryEnabled(context)).thenReturn(true);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getLoginPageFromXMLFile(any(AuthenticationContext.class)))
                .thenReturn("/authenticationendpoint/voiceOtpError.jsp");
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        invokePrivateMethod(authenticator, "checkStatusCode",
                new Class[]{HttpServletResponse.class, AuthenticationContext.class, String.class, String.class},
                response, context, null, VoiceOTPConstants.ERROR_PAGE);
        verify(response).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(VoiceOTPConstants.AUTHENTICATOR_NAME));
    }

    @Test
    public void testCheckStatusCodeWithNullValue() throws Exception {
        context.setProperty(VoiceOTPConstants.STATUS_CODE, null);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isRetryEnabled(context)).thenReturn(true);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getLoginPageFromXMLFile(any(AuthenticationContext.class)))
                .thenReturn("/authenticationendpoint/voiceOtp.jsp");
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        invokePrivateMethod(authenticator, "checkStatusCode",
                new Class[]{HttpServletResponse.class, AuthenticationContext.class, String.class, String.class},
                response, context, null, VoiceOTPConstants.ERROR_PAGE);
        verify(response).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(VoiceOTPConstants.AUTHENTICATOR_NAME));
    }

    @Test
    public void testCheckStatusCodeWithMismatch() throws Exception {
        context.setProperty(VoiceOTPConstants.CODE_MISMATCH, "true");
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isRetryEnabled(context)).thenReturn(false);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isEnableResendCode(context)).thenReturn(true);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getLoginPageFromXMLFile(any(AuthenticationContext.class)))
                .thenReturn("/authenticationendpoint/voiceOtpError.jsp");
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        invokePrivateMethod(authenticator, "checkStatusCode",
                new Class[]{HttpServletResponse.class, AuthenticationContext.class, String.class, String.class},
                response, context, null, VoiceOTPConstants.ERROR_PAGE);
        verify(response).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(VoiceOTPConstants.ERROR_CODE_MISMATCH));
    }

    @Test
    public void testCheckStatusCodeWithTokenExpired() throws Exception {
        context.setProperty(VoiceOTPConstants.TOKEN_EXPIRED, "token.expired");
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isEnableResendCode(context)).thenReturn(true);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isRetryEnabled(context)).thenReturn(true);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getLoginPageFromXMLFile(any(AuthenticationContext.class)))
                .thenReturn("/authenticationendpoint/voiceOtp.jsp");
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        invokePrivateMethod(authenticator, "checkStatusCode",
                new Class[]{HttpServletResponse.class, AuthenticationContext.class, String.class, String.class},
                response, context, null, VoiceOTPConstants.VOICE_LOGIN_PAGE);
        verify(response).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(VoiceOTPConstants.TOKEN_EXPIRED_VALUE));
    }

    @Test
    public void testProcessVoiceOTPFlow() throws Exception {
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isVoiceOTPDisableForLocalUser("John@carbon.super", context)).thenReturn(true);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getErrorPageFromXMLFile(any(AuthenticationContext.class)))
                .thenReturn(VoiceOTPConstants.ERROR_PAGE);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isEnableMobileNoUpdate(any(AuthenticationContext.class)))
                .thenReturn(true);
        context.setProperty(VoiceOTPConstants.MOBILE_NUMBER_UPDATE_FAILURE, "true");
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        invokePrivateMethod(authenticator, "processVoiceOTPFlow",
                new Class[]{AuthenticationContext.class, HttpServletRequest.class, HttpServletResponse.class,
                        boolean.class, String.class, String.class, String.class, String.class},
                context, httpServletRequest, response, true, "John@carbon.super", "", "carbon.super",
                VoiceOTPConstants.ERROR_PAGE);
        verify(response).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(VoiceOTPConstants.AUTHENTICATOR_NAME));
    }

    @Test
    public void testSendOTPDirectlyToMobile() throws Exception {
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isSendOTPDirectlyToMobile(context)).thenReturn(true);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getMobileNumberRequestPage(any(AuthenticationContext.class)))
                .thenReturn("/authenticationendpoint/mobile.jsp");
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        invokePrivateMethod(authenticator, "processVoiceOTPFlow",
                new Class[]{AuthenticationContext.class, HttpServletRequest.class, HttpServletResponse.class,
                        boolean.class, String.class, String.class, String.class, String.class},
                context, httpServletRequest, response, false, "John@carbon.super", "", "carbon.super",
                VoiceOTPConstants.ERROR_PAGE);
        verify(response).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(VoiceOTPConstants.AUTHENTICATOR_NAME));
    }

    @Test
    public void testProcessVoiceOTPDisableFlow() throws Exception {
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isSendOTPDirectlyToMobile(context)).thenReturn(false);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getErrorPageFromXMLFile(any(AuthenticationContext.class)))
                .thenReturn(VoiceOTPConstants.ERROR_PAGE);
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        invokePrivateMethod(authenticator, "processVoiceOTPFlow",
                new Class[]{AuthenticationContext.class, HttpServletRequest.class, HttpServletResponse.class,
                        boolean.class, String.class, String.class, String.class, String.class},
                context, httpServletRequest, response, false, "John@carbon.super", "", "carbon.super",
                VoiceOTPConstants.ERROR_PAGE);
        verify(response).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(VoiceOTPConstants.SEND_OTP_DIRECTLY_DISABLE));
    }

    @Test
    public void testProcessWithLogoutTrue() throws AuthenticationFailedException, LogoutFailedException {
        doReturn(true).when(context).isLogoutRequest();
        AuthenticatorFlowStatus status = authenticator.process(httpServletRequest, response, context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    @Test
    public void testProcessWithLogoutFalse() throws Exception {
        doReturn(false).when(context).isLogoutRequest();
        Mockito.when(httpServletRequest.getParameter(VoiceOTPConstants.MOBILE_NUMBER)).thenReturn("true");
        context.setTenantDomain("carbon.super");
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier("admin");
        doReturn(otpTime).when(context).getProperty(VoiceOTPConstants.OTP_GENERATED_TIME);
        doReturn(authenticatedUser).when(context).getProperty(VoiceOTPConstants.AUTHENTICATED_USER);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isVoiceOTPMandatory(context)).thenReturn(true);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getErrorPageFromXMLFile(context))
                .thenReturn(VoiceOTPConstants.ERROR_PAGE);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isSendOTPDirectlyToMobile(context)).thenReturn(false);
        mockedFrameworkUtils.when(() -> FrameworkUtils.getQueryStringWithFrameworkContextId(
                context.getQueryParams(), context.getCallerSessionKey(), context.getContextIdentifier()))
                .thenReturn(null);
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        invokePrivateMethod(authenticator, "processVoiceOTPFlow",
                new Class[]{AuthenticationContext.class, HttpServletRequest.class, HttpServletResponse.class,
                        boolean.class, String.class, String.class, String.class, String.class},
                context, httpServletRequest, response, false, "John@carbon.super", "", "carbon.super",
                VoiceOTPConstants.ERROR_PAGE);
        verify(response).sendRedirect(captor.capture());
        AuthenticatorFlowStatus status = authenticator.process(httpServletRequest, response, context);
        Assert.assertTrue(captor.getValue().contains(VoiceOTPConstants.SEND_OTP_DIRECTLY_DISABLE));
        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
    }

    @Test
    public void testProcessWithLogout() throws AuthenticationFailedException, LogoutFailedException {
        doReturn(false).when(context).isLogoutRequest();
        Mockito.when(httpServletRequest.getParameter(VoiceOTPConstants.CODE)).thenReturn("");
        context.setTenantDomain("carbon.super");
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier("admin");
        authenticatedUser.setUserName("testUser");
        authenticatedUser.setUserStoreDomain("secondary");
        context.setProperty(VoiceOTPConstants.SENT_OTP_TOKEN_TIME, otpTime);
        doReturn(authenticatedUser).when(context).getProperty(VoiceOTPConstants.AUTHENTICATED_USER);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isVoiceOTPMandatory(context)).thenReturn(true);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getErrorPageFromXMLFile(context))
                .thenReturn(VoiceOTPConstants.ERROR_PAGE);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isSendOTPDirectlyToMobile(context)).thenReturn(false);
        mockedFrameworkUtils.when(() -> FrameworkUtils.getQueryStringWithFrameworkContextId(
                context.getQueryParams(), context.getCallerSessionKey(), context.getContextIdentifier()))
                .thenReturn(null);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getBackupCode(context)).thenReturn("false");

        AuthenticatorFlowStatus status = authenticator.process(httpServletRequest, response, context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
    }

    @Test
    public void testInitiateAuthenticationRequestWithVoiceOTPMandatory() throws Exception {
        context.setTenantDomain("carbon.super");
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier("admin");
        doReturn(authenticatedUser).when(context).getProperty(VoiceOTPConstants.AUTHENTICATED_USER);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isVoiceOTPMandatory(context)).thenReturn(true);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getErrorPageFromXMLFile(context))
                .thenReturn(VoiceOTPConstants.ERROR_PAGE);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isSendOTPDirectlyToMobile(context)).thenReturn(false);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getErrorPageFromXMLFile(any(AuthenticationContext.class)))
                .thenReturn(VoiceOTPConstants.ERROR_PAGE);
        mockedFrameworkUtils.when(() -> FrameworkUtils.getQueryStringWithFrameworkContextId(
                context.getQueryParams(), context.getCallerSessionKey(), context.getContextIdentifier()))
                .thenReturn(null);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getBackupCode(context)).thenReturn("false");
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        invokePrivateMethod(authenticator, "initiateAuthenticationRequest",
                new Class[]{HttpServletRequest.class, HttpServletResponse.class, AuthenticationContext.class},
                httpServletRequest, response, context);
        verify(response).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(VoiceOTPConstants.SEND_OTP_DIRECTLY_DISABLE));
    }

    @Test
    public void testInitiateAuthenticationRequestWithVoiceOTPOptional() throws Exception {
        context.setTenantDomain("carbon.super");
        context.setProperty(VoiceOTPConstants.TOKEN_EXPIRED, "token.expired");
        doReturn(true).when(context).isRetrying();
        Mockito.when(httpServletRequest.getParameter(VoiceOTPConstants.RESEND)).thenReturn("false");
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier("admin");
        doReturn(authenticatedUser).when(context).getProperty(VoiceOTPConstants.AUTHENTICATED_USER);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isVoiceOTPMandatory(context)).thenReturn(false);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isRetryEnabled(context)).thenReturn(true);
        mockedFederatedAuthenticatorUtil.when(() -> FederatedAuthenticatorUtil.isUserExistInUserStore(anyString()))
                .thenReturn(true);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getMobileNumberForUsername(anyString()))
                .thenReturn("0778965320");
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getLoginPageFromXMLFile(any(AuthenticationContext.class)))
                .thenReturn(VoiceOTPConstants.LOGIN_PAGE);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getErrorPageFromXMLFile(any(AuthenticationContext.class)))
                .thenReturn(VoiceOTPConstants.ERROR_PAGE);
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        invokePrivateMethod(authenticator, "initiateAuthenticationRequest",
                new Class[]{HttpServletRequest.class, HttpServletResponse.class, AuthenticationContext.class},
                httpServletRequest, response, context);
        verify(response).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(VoiceOTPConstants.TOKEN_EXPIRED_VALUE));
    }

    @Test(expectedExceptions = {AuthenticationFailedException.class})
    public void testInitiateAuthenticationRequestWithoutAuthenticatedUser() throws Exception {
        context.setTenantDomain("carbon.super");
        invokePrivateMethod(authenticator, "initiateAuthenticationRequest",
                new Class[]{HttpServletRequest.class, HttpServletResponse.class, AuthenticationContext.class},
                httpServletRequest, response, context);
    }

    @Test(expectedExceptions = {InvalidCredentialsException.class})
    public void testProcessAuthenticationResponseWithoutOTPCode() throws Exception {
        Mockito.when(httpServletRequest.getParameter(VoiceOTPConstants.CODE)).thenReturn("");
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isLocalUser(context)).thenReturn(true);
        invokePrivateMethod(authenticator, "processAuthenticationResponse",
                new Class[]{HttpServletRequest.class, HttpServletResponse.class, AuthenticationContext.class},
                httpServletRequest, response, context);
    }

    @Test(expectedExceptions = {InvalidCredentialsException.class})
    public void testProcessAuthenticationResponseWithResend() throws Exception {
        Mockito.when(httpServletRequest.getParameter(VoiceOTPConstants.CODE)).thenReturn("123456");
        Mockito.when(httpServletRequest.getParameter(VoiceOTPConstants.RESEND)).thenReturn("true");
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isLocalUser(context)).thenReturn(true);
        invokePrivateMethod(authenticator, "processAuthenticationResponse",
                new Class[]{HttpServletRequest.class, HttpServletResponse.class, AuthenticationContext.class},
                httpServletRequest, response, context);
    }

    @Test
    public void testProcessAuthenticationResponse() throws Exception {
        Mockito.when(httpServletRequest.getParameter(VoiceOTPConstants.CODE)).thenReturn("123456");
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier("admin");
        authenticatedUser.setUserId("4b4414e1-916b-4475-aaee-6b0751c29ff6");
        authenticatedUser.setUserName("admin");
        authenticatedUser.setTenantDomain("carbon.super");
        StepConfig stepConfig = new StepConfig();
        stepConfig.setSubjectAttributeStep(true);
        stepConfig.setAuthenticatedUser(authenticatedUser);
        context.setProperty(VoiceOTPConstants.CODE_MISMATCH, false);
        context.setProperty(VoiceOTPConstants.OTP_TOKEN, "123456");
        context.setProperty(VoiceOTPConstants.TOKEN_VALIDITY_TIME, "");
        context.setSequenceConfig(new SequenceConfig());
        context.getSequenceConfig().getStepMap().put(1, stepConfig);
        invokePrivateMethod(authenticator, "getAuthenticatedUser",
                new Class[]{AuthenticationContext.class},
                context);
        Property property = new Property();
        property.setName(VoiceOTPConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE);
        property.setValue("true");
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getAccountLockConnectorConfigs(authenticatedUser.getTenantDomain()))
                .thenReturn(new Property[]{property});
        mockedIdentityTenantUtil.when(() -> IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        mockedIdentityTenantUtil.when(IdentityTenantUtil::getRealmService).thenReturn(realmService);
        Mockito.when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        Mockito.when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);

        invokePrivateMethod(authenticator, "processAuthenticationResponse",
                new Class[]{HttpServletRequest.class, HttpServletResponse.class, AuthenticationContext.class},
                httpServletRequest, response, context);
    }

    @Test
    public void testProcessAuthenticationResponseWithvalidBackupCode() throws Exception {
        Mockito.when(httpServletRequest.getParameter(VoiceOTPConstants.CODE)).thenReturn("123456");
        context.setProperty(VoiceOTPConstants.OTP_TOKEN, "123456");
        context.setProperty(VoiceOTPConstants.USER_NAME, "admin");
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier("admin");
        authenticatedUser.setUserName("admin");
        doReturn(authenticatedUser).when(context).getProperty(VoiceOTPConstants.AUTHENTICATED_USER);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getBackupCode(context)).thenReturn("true");

        mockedIdentityTenantUtil.when(() -> IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        mockedIdentityTenantUtil.when(IdentityTenantUtil::getRealmService).thenReturn(realmService);
        Mockito.when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        Mockito.when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        Mockito.when(userStoreManager
                .getUserClaimValue("admin@carbon.super", VoiceOTPConstants.SAVED_OTP_LIST, null))
                .thenReturn("123456,789123");
        mockedFrameworkUtils.when(FrameworkUtils::getMultiAttributeSeparator).thenReturn(",");

        Property property = new Property();
        property.setName(VoiceOTPConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE);
        property.setValue("true");
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getAccountLockConnectorConfigs(authenticatedUser.getTenantDomain()))
                .thenReturn(new Property[]{property});
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isLocalUser(context)).thenReturn(true);
        Mockito.when(userStoreManager.getClaimManager()).thenReturn(claimManager);
        Mockito.when(userStoreManager.getClaimManager().getClaim(VoiceOTPConstants.SAVED_OTP_LIST))
                .thenReturn(claim);
        doReturn(false).when(context).getProperty(VoiceOTPConstants.CODE_MISMATCH);

        SequenceConfig sequenceConfig = new SequenceConfig();
        Map<Integer, StepConfig> stepMap = new HashMap<>();

        StepConfig stepConfig = new StepConfig();
        stepConfig.setSubjectAttributeStep(true);

        AuthenticatedUser authUser = new AuthenticatedUser();
        stepConfig.setAuthenticatedUser(authUser);

        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isAccountLocked(authenticatedUser)).thenReturn(false);

        stepMap.put(1, stepConfig);
        sequenceConfig.setStepMap(stepMap);

        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isLocalUser(context)).thenReturn(true);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getBackupCode(context)).thenReturn("true");

        doReturn(new SequenceConfig()).when(context).getSequenceConfig();

        invokePrivateMethod(authenticator, "processAuthenticationResponse",
                new Class[]{HttpServletRequest.class, HttpServletResponse.class, AuthenticationContext.class},
                httpServletRequest, response, context);
    }

    @Test(expectedExceptions = {AuthenticationFailedException.class})
    public void testProcessAuthenticationResponseWithCodeMismatch() throws Exception {
        Mockito.when(httpServletRequest.getParameter(VoiceOTPConstants.CODE)).thenReturn("123456");
        context.setProperty(VoiceOTPConstants.OTP_TOKEN, "123");
        context.setProperty(VoiceOTPConstants.USER_NAME, "admin");
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier("admin");
        authenticatedUser.setTenantDomain("carbon.super");
        doReturn(authenticatedUser).when(context).getProperty(VoiceOTPConstants.AUTHENTICATED_USER);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getBackupCode(context)).thenReturn("false");

        Property property = new Property();
        property.setName(VoiceOTPConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE);
        property.setValue("true");
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getAccountLockConnectorConfigs(authenticatedUser.getTenantDomain()))
                .thenReturn(new Property[]{property});

        mockedIdentityTenantUtil.when(() -> IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        mockedIdentityTenantUtil.when(IdentityTenantUtil::getRealmService).thenReturn(realmService);
        Mockito.when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        Mockito.when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);

        SequenceConfig sequenceConfig = new SequenceConfig();
        Map<Integer, StepConfig> stepMap = new HashMap<>();

        StepConfig stepConfig = new StepConfig();
        stepConfig.setSubjectAttributeStep(true);

        AuthenticatedUser authUser = new AuthenticatedUser();
        stepConfig.setAuthenticatedUser(authUser);

        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isAccountLocked(authenticatedUser)).thenReturn(false);

        stepMap.put(1, stepConfig);
        sequenceConfig.setStepMap(stepMap);

        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isLocalUser(context)).thenReturn(true);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getBackupCode(context)).thenReturn("true");

        doReturn(new SequenceConfig()).when(context).getSequenceConfig();

        invokePrivateMethod(authenticator, "processAuthenticationResponse",
                new Class[]{HttpServletRequest.class, HttpServletResponse.class, AuthenticationContext.class},
                httpServletRequest, response, context);
    }

    @Test
    public void testCheckWithBackUpCodes() throws Exception {
        context.setProperty(VoiceOTPConstants.USER_NAME, "admin");
        mockedIdentityTenantUtil.when(() -> IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        mockedIdentityTenantUtil.when(IdentityTenantUtil::getRealmService).thenReturn(realmService);
        Mockito.when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        Mockito.when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier("admin");
        doReturn(authenticatedUser).when(context).getProperty(VoiceOTPConstants.AUTHENTICATED_USER);
        Mockito.when(userRealm.getUserStoreManager()
                .getUserClaimValue(MultitenantUtils.getTenantAwareUsername("admin"),
                        VoiceOTPConstants.SAVED_OTP_LIST, null)).thenReturn("12345,4568,1234,7896");
        AuthenticatedUser user = (AuthenticatedUser) context.getProperty(VoiceOTPConstants.AUTHENTICATED_USER);
        mockedFrameworkUtils.when(FrameworkUtils::getMultiAttributeSeparator).thenReturn(",");
        invokePrivateMethod(authenticator, "checkWithBackUpCodes",
                new Class[]{AuthenticationContext.class, String.class, AuthenticatedUser.class},
                context, "1234", user);
    }

    public void testCheckWithInvalidBackUpCodes() throws Exception {
        context.setProperty(VoiceOTPConstants.USER_NAME, "admin");
        mockedIdentityTenantUtil.when(() -> IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        mockedIdentityTenantUtil.when(IdentityTenantUtil::getRealmService).thenReturn(realmService);
        Mockito.when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        Mockito.when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier("admin");
        doReturn(authenticatedUser).when(context).getProperty(VoiceOTPConstants.AUTHENTICATED_USER);
        mockedFrameworkUtils.when(FrameworkUtils::getMultiAttributeSeparator).thenReturn(",");
        Mockito.when(userRealm.getUserStoreManager()
                .getUserClaimValue(MultitenantUtils.getTenantAwareUsername("admin"),
                        VoiceOTPConstants.SAVED_OTP_LIST, null)).thenReturn("12345,4568,1234,7896");
        invokePrivateMethod(authenticator, "checkWithBackUpCodes",
                new Class[]{AuthenticationContext.class, String.class, AuthenticatedUser.class},
                context, "45698789", authenticatedUser);
    }

    @Test
    public void testGetScreenAttribute() throws org.wso2.carbon.user.api.UserStoreException {
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getScreenUserAttribute(context))
                .thenReturn("http://wso2.org/claims/mobile");
        mockedIdentityTenantUtil.when(() -> IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        mockedIdentityTenantUtil.when(IdentityTenantUtil::getRealmService).thenReturn(realmService);
        Mockito.when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        Mockito.when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        Mockito.when(userRealm.getUserStoreManager()
                .getUserClaimValue("admin", "http://wso2.org/claims/mobile", null))
                .thenReturn("0778965231");
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getNoOfDigits(context)).thenReturn("4");

        Assert.assertEquals(authenticator.getScreenAttribute(context, userRealm, "admin"), "0778******");

        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getDigitsOrder(context)).thenReturn("backward");
        Assert.assertEquals(authenticator.getScreenAttribute(context, userRealm, "admin"), "******5231");
    }

    @Test
    public void testGetScreenAttributeWhenMobileRequest() throws org.wso2.carbon.user.api.UserStoreException {
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getScreenUserAttribute(context))
                .thenReturn("http://wso2.org/claims/mobile");
        doReturn("0778899889").when(context).getProperty(REQUESTED_USER_MOBILE);
        mockedIdentityTenantUtil.when(() -> IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        mockedIdentityTenantUtil.when(IdentityTenantUtil::getRealmService).thenReturn(realmService);
        Mockito.when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        Mockito.when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        Mockito.when(userRealm.getUserStoreManager()
                .getUserClaimValue("admin", "http://wso2.org/claims/mobile", null)).thenReturn(null);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getNoOfDigits(context)).thenReturn("4");

        Assert.assertEquals(authenticator.getScreenAttribute(context, userRealm, "admin"), "0778******");

        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getDigitsOrder(context)).thenReturn("backward");
        Assert.assertEquals(authenticator.getScreenAttribute(context, userRealm, "admin"), "******9889");
    }

    @Test
    public void testUpdateMobileNumberForUsername() throws Exception {
        mockedIdentityTenantUtil.when(() -> IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        mockedIdentityTenantUtil.when(IdentityTenantUtil::getRealmService).thenReturn(realmService);
        Mockito.when(realmService.getTenantUserRealm(-1234)).thenReturn(null);
        invokePrivateMethod(authenticator, "updateMobileNumberForUsername",
                new Class[]{AuthenticationContext.class, HttpServletRequest.class, String.class, String.class},
                context, httpServletRequest, "admin", "carbon.super");
    }

    @Test
    public void testGetConfigurationProperties() {
        List<Property> configProperties = new ArrayList<>();
        Property voiceUrl = new Property();
        configProperties.add(voiceUrl);
        Property httpMethod = new Property();
        configProperties.add(httpMethod);
        Property headers = new Property();
        configProperties.add(headers);
        Property payload = new Property();
        configProperties.add(payload);
        Property httpResponse = new Property();
        configProperties.add(httpResponse);
        Property otpSeparator = new Property();
        configProperties.add(otpSeparator);
        Property otpDigitSeparator = new Property();
        configProperties.add(otpDigitSeparator);
        Property divisor = new Property();
        configProperties.add(divisor);
        Property showErrorInfo = new Property();
        configProperties.add(showErrorInfo);
        Property maskValues = new Property();
        configProperties.add(maskValues);
        Property mobileNumberRegexPattern = new Property();
        configProperties.add(mobileNumberRegexPattern);
        Property mobileNumberPatternFailureErrorMessage = new Property();
        configProperties.add(mobileNumberPatternFailureErrorMessage);
        Assert.assertEquals(configProperties.size(), authenticator.getConfigurationProperties().size());
    }

    @Test
    public void testDefaultOtpSeparationCharacters() throws Exception {
        Assert.assertEquals(invokePrivateMethod(authenticator, "getOTPSeparationCharacters",
                new Class[]{AuthenticationContext.class}, context), "%2B");
    }

    @Test
    public void testOtpSeparationCharacters() throws Exception {
        doReturn(authenticatorProperties).when(context).getAuthenticatorProperties();
        Mockito.when(authenticatorProperties.get(OTP_SEPARATOR)).thenReturn("%20");
        Assert.assertEquals(invokePrivateMethod(authenticator, "getOTPSeparationCharacters",
                new Class[]{AuthenticationContext.class}, context), "%20");
    }

    @Test
    public void testDefaultDivisorValue() throws Exception {
        Assert.assertEquals(Integer.toString((Integer) invokePrivateMethod(authenticator, "getDivisor",
                new Class[]{AuthenticationContext.class}, context)), "1");
    }

    @Test
    public void testDivisorValue() throws Exception {
        doReturn(authenticatorProperties).when(context).getAuthenticatorProperties();
        Mockito.when(authenticatorProperties.get(DIVISOR)).thenReturn("2");
        Assert.assertEquals(Integer.toString((Integer) invokePrivateMethod(authenticator, "getDivisor",
                new Class[]{AuthenticationContext.class}, context)), "2");
    }

    @Test
    public void testOtpSeparation() throws Exception {
        doReturn(authenticatorProperties).when(context).getAuthenticatorProperties();
        Mockito.when(authenticatorProperties.get(OTP_SEPARATOR)).thenReturn("%20");
        Mockito.when(authenticatorProperties.get(DIVISOR)).thenReturn("2");
        Assert.assertEquals(invokePrivateMethod(authenticator, "splitAndFormatOtp",
                new Class[]{String.class, int.class, AuthenticationContext.class},
                "123456", 2, context), "12%2034%2056");
    }

    @Test
    public void testSuccessfulGetConnection() throws Exception {
        String receivedMobileNumber = "1234567890";
        String otpToken = "123456";
        Integer httpResponse = 200;
        URL url = new URL("https://google.lk");

        httpURLConnection = (HttpURLConnection) url.openConnection();

        httpURLConnection.setRequestMethod("GET");
        httpURLConnection.setDoOutput(true);
        httpURLConnection.setDoInput(true);

        Assert.assertEquals(invokePrivateMethod(authenticator, "getConnection",
                new Class[]{HttpURLConnection.class, AuthenticationContext.class, String.class, String.class,
                        String.class, String.class, String.class, String.class},
                httpURLConnection, context, null, null,
                httpResponse.toString(), receivedMobileNumber, otpToken, "GET"), Boolean.TRUE);
    }

    @Test
    public void testGetConnectionWithUnauthorizedResponse() throws Exception {
        String headerString = "Content-Type:application/json";
        String payload = "{\"key\":\"value\"}";
        String httpMethod = "POST";

        URL url = new URL("https://google.lk");

        httpURLConnection = (HttpURLConnection) Mockito.mock(url.openConnection().getClass());
        Mockito.when(httpURLConnection.getResponseCode()).thenReturn(401);
        Mockito.when(httpURLConnection.getResponseMessage()).thenReturn("Unauthorized");
        Mockito.when(httpURLConnection.getOutputStream()).thenReturn(new OutputStream() {
            @Override
            public void write(int b) throws IOException {
            }
        });

        boolean result = (boolean) invokePrivateMethod(authenticator, "getConnection",
                new Class[]{HttpURLConnection.class, AuthenticationContext.class, String.class, String.class,
                        String.class, String.class, String.class, String.class},
                httpURLConnection, context, headerString, payload, null,
                "0713933424", null, httpMethod);

        Assert.assertFalse(result);
        verify(httpURLConnection).setRequestMethod("POST");
        verify(httpURLConnection).setRequestProperty("Content-Type", "application/json");
    }

    @Test
    public void testGetConnectionWithSuccessfulResponse() throws Exception {
        String headerString = "Content-Type:application/json";
        String payload = "{\"key\":\"value\"}";
        String httpMethod = "POST";

        URL url = new URL("https://google.lk");

        httpURLConnection = (HttpURLConnection) Mockito.mock(url.openConnection().getClass());
        Mockito.when(httpURLConnection.getResponseCode()).thenReturn(200);
        Mockito.when(httpURLConnection.getResponseMessage()).thenReturn("OK");
        Mockito.when(httpURLConnection.getOutputStream()).thenReturn(new ByteArrayOutputStream());

        boolean result = (boolean) invokePrivateMethod(authenticator, "getConnection",
                new Class[]{HttpURLConnection.class, AuthenticationContext.class, String.class, String.class,
                        String.class, String.class, String.class, String.class},
                httpURLConnection, context, headerString, payload,
                null, "07123456789", null, httpMethod);

        Assert.assertTrue(result);
        verify(httpURLConnection).setRequestMethod("POST");
        verify(httpURLConnection).setRequestProperty("Content-Type", "application/json");
    }

    @Test
    public void testProceedWithOTPSuccess() throws Exception {
        String errorPage = "errorPage";
        String mobileNumber = "1234567890";
        String queryParams = "queryParams";
        String username = "testUser";

        Map<String, String> authProps = new HashMap<>();
        authProps.put(VoiceOTPConstants.VOICE_URL, "http://google.lk");
        authProps.put(VoiceOTPConstants.HTTP_METHOD, "POST");
        doReturn(authProps).when(context).getAuthenticatorProperties();
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getLoginPageFromXMLFile(context))
                .thenReturn("authenticationendpoint/voiceOtp.jsp");
        Mockito.when(configurationFacade.getAuthenticationEndpointURL())
                .thenReturn("/authenticationendpoint/login.do");
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getTokenLength(context)).thenReturn("6");
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getTokenExpiryTime(context)).thenReturn("300");
        mockedOneTimePasswordUtils.when(() -> OneTimePasswordUtils.getRandomNumber(VoiceOTPConstants.SECRET_KEY_LENGTH))
                .thenReturn("123456");

        byte[] test = "12345".getBytes();
        Long testL = Long.parseLong("12345");

        mockedOneTimePasswordUtils.when(() -> OneTimePasswordUtils.generateToken("123456", "2", 6, false))
                .thenReturn("123456");
        mockedOneTimePasswordUtils.when(() -> OneTimePasswordUtils.generateOTP(test, testL, 6, false, 1))
                .thenReturn("12345");

        invokeProceedWithOTPPrivateMethod(authenticator, "proceedWithOTP", response,
                context, errorPage, mobileNumber, queryParams, username);
        verify(response, times(1)).sendRedirect(anyString());
    }

    private void invokeProceedWithOTPPrivateMethod(Object instance, String methodName, Object... args)
            throws Exception {
        Method method = instance.getClass().getDeclaredMethod(methodName, HttpServletResponse.class,
                AuthenticationContext.class, String.class, String.class, String.class, String.class);
        method.setAccessible(true);
        method.invoke(instance, args);
    }

    @Test(expectedExceptions = {AuthenticationFailedException.class})
    public void testSendRestCall() throws AuthenticationFailedException, IOException {
        String header = "Authorization: Basic dGVzdDp0ZXN0";
        String httpMethod = "POST";
        String payload = "{\"key\":\"key\",\"value\":\"value\"}";
        String voiceURL = "http://127.0.0.1:1/voice";
        String httpResponse = "200";

        authenticator.sendRESTCall(context, voiceURL, httpMethod, header, payload,
                httpResponse, "+94713933424", "123456");
    }

    @Test
    public void testGetMultiOptionURIQueryParam_RequestIsNull() throws Exception {
        HttpServletRequest request = null;

        String result = (String) invokePrivateMethod(authenticator, "getMultiOptionURIQueryParam",
                new Class[]{HttpServletRequest.class}, request);

        Assert.assertEquals(StringUtils.EMPTY, result);
    }

    @Test
    public void testGetMultiOptionURIQueryParam_ParameterIsEmpty() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        Mockito.when(request.getParameter(VoiceOTPConstants.MULTI_OPTION_URI)).thenReturn("");

        String result = (String) invokePrivateMethod(authenticator, "getMultiOptionURIQueryParam",
                new Class[]{HttpServletRequest.class}, request);

        Assert.assertEquals(StringUtils.EMPTY, result);
    }

    @Test
    public void testGetMultiOptionURIQueryParam_ParameterIsNotEmpty() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        String expectedValue = "someValue";
        Mockito.when(request.getParameter(VoiceOTPConstants.MULTI_OPTION_URI)).thenReturn(expectedValue);

        String result = (String) invokePrivateMethod(authenticator, "getMultiOptionURIQueryParam",
                new Class[]{HttpServletRequest.class}, request);

        String expectedQueryParam = "&" +
                VoiceOTPConstants.MULTI_OPTION_URI + "=" + Encode.forUriComponent(expectedValue);
        Assert.assertEquals(expectedQueryParam, result);
    }

    @Test
    public void testGetMultiOptionURIQueryParam_ParrameterIsNull() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        Mockito.when(request.getParameter(VoiceOTPConstants.MULTI_OPTION_URI)).thenReturn(null);

        Assert.assertEquals(invokePrivateMethod(authenticator, "getMultiOptionURIQueryParam",
                new Class[]{HttpServletRequest.class}, request), StringUtils.EMPTY);
    }

    @Test
    public void testHandleVoiceOtpVerificationFailWhenLocalUserWithAccountLockingDisabled() throws Exception {
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isLocalUser(context)).thenReturn(false);
        invokeHandleVoiceOtpVerificationFailPrivateMethod(authenticator,
                "handleVoiceOtpVerificationFail", context);
        Assert.assertFalse(VoiceOTPUtils.isAccountLockingEnabledForVoiceOtp(context));
    }

    private void invokeHandleVoiceOtpVerificationFailPrivateMethod(Object instance, String methodName, Object... args)
            throws Exception {
        Method method = instance.getClass().getDeclaredMethod(methodName, AuthenticationContext.class);
        method.setAccessible(true);
        method.invoke(instance, args);
    }

    @Test
    public void testHandleVoiceOtpVerificationFailWhenAccountAlreadyLocked() throws Exception {
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isLocalUser(context)).thenReturn(true);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isAccountLockingEnabledForVoiceOtp(context)).thenReturn(true);
        doReturn(authenticatedUser).when(context).getProperty(VoiceOTPConstants.AUTHENTICATED_USER);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isAccountLocked(authenticatedUser)).thenReturn(true);
        invokeHandleVoiceOtpVerificationFailPrivateMethod(authenticator,
                "handleVoiceOtpVerificationFail", context);
        Assert.assertTrue(VoiceOTPUtils.isAccountLockingEnabledForVoiceOtp(context));
    }

    @Test
    public void testHandleVoiceOtpVerificationFailWhenMaxAttemptsExceeded() throws Exception {
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isLocalUser(context)).thenReturn(true);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isAccountLockingEnabledForVoiceOtp(context)).thenReturn(true);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isAccountLocked(authenticatedUser)).thenReturn(false);
        doReturn(authenticatedUser).when(context).getProperty(VoiceOTPConstants.AUTHENTICATED_USER);
        Mockito.when(authenticatedUser.getTenantDomain()).thenReturn("testdomain");

        Property accountLockOnFailure = new Property();
        accountLockOnFailure.setName(VoiceOTPConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE);
        accountLockOnFailure.setDefaultValue("true");
        Property accountLockOnFailureMax = new Property();
        accountLockOnFailureMax.setName(VoiceOTPConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE_MAX);
        accountLockOnFailureMax.setDefaultValue("3");
        Property accountLockTime = new Property();
        accountLockTime.setName(VoiceOTPConstants.PROPERTY_ACCOUNT_LOCK_TIME);
        accountLockTime.setDefaultValue("5");
        Property loginFailTimeoutRatio = new Property();
        loginFailTimeoutRatio.setName(VoiceOTPConstants.PROPERTY_LOGIN_FAIL_TIMEOUT_RATIO);
        loginFailTimeoutRatio.setDefaultValue("1.5");

        Property[] properties = new Property[]{accountLockOnFailure, accountLockTime,
                loginFailTimeoutRatio, accountLockOnFailureMax};
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getAccountLockConnectorConfigs("testdomain"))
                .thenReturn(properties);

        Map<String, String> claims = new HashMap<>();
        claims.put(VoiceOTPConstants.VOICE_OTP_FAILED_ATTEMPTS_CLAIM, "2");
        claims.put(VoiceOTPConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM, "1");
        Mockito.when(userStoreManager.getUserClaimValues(anyString(), any(), anyString()))
                .thenReturn(claims);

        invokehandleVoiceOtpVerificationFailPrivateMethod(authenticator,
                "handleVoiceOtpVerificationFail", context);

        mockedVoiceOTPUtils.verify(() -> VoiceOTPUtils.getAccountLockConnectorConfigs(anyString()), times(1));
    }

    private void invokehandleVoiceOtpVerificationFailPrivateMethod(Object instance, String methodName, Object... args)
            throws Exception {
        Method method = instance.getClass().getDeclaredMethod(methodName, AuthenticationContext.class);
        method.setAccessible(true);
        method.invoke(instance, args);
    }

    @Test(expectedExceptions = Exception.class)
    public void testHandleVoiceOtpVerificationFailIncrementalFailure() throws Exception {
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isLocalUser(context)).thenReturn(true);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isAccountLockingEnabledForVoiceOtp(context)).thenReturn(true);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isAccountLocked(authenticatedUser)).thenReturn(false);
        doReturn(authenticatedUser).when(context).getProperty(VoiceOTPConstants.AUTHENTICATED_USER);
        Mockito.when(authenticatedUser.getTenantDomain()).thenReturn("testdomain");

        Property accountLockOnFailureMax = new Property();
        accountLockOnFailureMax.setName(VoiceOTPConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE_MAX);
        accountLockOnFailureMax.setDefaultValue("3");

        Property[] properties = new Property[]{accountLockOnFailureMax};
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getAccountLockConnectorConfigs("testdomain"))
                .thenReturn(properties);

        Map<String, String> claims = new HashMap<>();
        claims.put(VoiceOTPConstants.VOICE_OTP_FAILED_ATTEMPTS_CLAIM, "1");
        Mockito.when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        Mockito.when(userStoreManager.getUserClaimValues(anyString(), any(), anyString()))
                .thenReturn(claims);

        mockedIdentityTenantUtil.when(() -> IdentityTenantUtil.getTenantId("testdomain")).thenReturn(1);
        mockedIdentityTenantUtil.when(IdentityTenantUtil::getRealmService).thenReturn(realmService);
        Mockito.when(realmService.getTenantUserRealm(1)).thenReturn(userRealm);

        invokehandleVoiceOtpVerificationFailPrivateMethod(authenticator, "handleVoiceOtpVerificationFail", context);
    }

    @Test
    public void testResetVoiceOtpFailedAttemptsWhenAccountLockingEnabledOrFederatedFlow() throws Exception {
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isLocalUser(context)).thenReturn(true);
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.isAccountLockingEnabledForVoiceOtp(context)).thenReturn(true);
        doReturn(authenticatedUser).when(context).getProperty(VoiceOTPConstants.AUTHENTICATED_USER);
        Mockito.when(authenticatedUser.getTenantDomain()).thenReturn("testdomain");

        Property accountLockOnFailure = new Property();
        accountLockOnFailure.setName(VoiceOTPConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE);
        accountLockOnFailure.setDefaultValue("false");

        Property[] properties = new Property[]{};
        mockedVoiceOTPUtils.when(() -> VoiceOTPUtils.getAccountLockConnectorConfigs("testdomain"))
                .thenReturn(properties);

        mockedIdentityUtil.when(() -> IdentityUtil.addDomainToName(authenticatedUser.getUserName(),
                authenticatedUser.getUserStoreDomain())).thenReturn("testuser@tenantdomain");
        mockedIdentityTenantUtil.when(() -> IdentityTenantUtil.getTenantId("testdomain")).thenReturn(1);
        mockedIdentityTenantUtil.when(IdentityTenantUtil::getRealmService).thenReturn(realmService);
        Mockito.when(realmService.getTenantUserRealm(1)).thenReturn(userRealm);

        Map<String, String> claims = new HashMap<>();
        claims.put(VoiceOTPConstants.VOICE_OTP_FAILED_ATTEMPTS_CLAIM, "1");
        Mockito.when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        Mockito.when(userStoreManager.getUserClaimValues(anyString(), any(), anyString()))
                .thenReturn(claims);

        invokeResetVoiceOtpFailedAttemptsPrivateMethod(authenticator, "resetVoiceOtpFailedAttempts", context);
    }

    private void invokeResetVoiceOtpFailedAttemptsPrivateMethod(Object instance, String methodName, Object... args)
            throws Exception {
        Method method = instance.getClass().getDeclaredMethod(methodName, AuthenticationContext.class);
        method.setAccessible(true);
        method.invoke(instance, args);
    }

    @Test(expectedExceptions = Exception.class)
    public void testGetUnlockTimeInMilliSecondsWhenUserRealmIsNull() throws Exception {
        String username = "testuser";
        Mockito.when(authenticatedUser.toFullQualifiedUsername()).thenReturn(username);
        mockedMultitenantUtils.when(() -> MultitenantUtils.getTenantAwareUsername(username))
                .thenReturn("testuser@testdomain");
        mockedIdentityTenantUtil.when(() -> IdentityTenantUtil.getTenantId("testdomain")).thenReturn(1);
        mockedIdentityTenantUtil.when(IdentityTenantUtil::getRealmService).thenReturn(realmService);
        Mockito.when(realmService.getTenantUserRealm(1)).thenReturn(null);
        Mockito.when(userRealm.getUserStoreManager()).thenReturn(null);
        invokegetUnlockTimeInMilliSecondsPrivateMethod(authenticator, "getUnlockTimeInMilliSeconds", authenticatedUser);
    }

    private void invokegetUnlockTimeInMilliSecondsPrivateMethod(Object instance, String methodName, Object... args)
            throws Exception {
        Method method = instance.getClass().getDeclaredMethod(methodName, AuthenticatedUser.class);
        method.setAccessible(true);
        method.invoke(instance, args);
    }

    @Test
    public void testGetUnlockTimeInMilliSecondsWhenClaimValueConfigured() throws Exception {
        String username = "testuser";
        String tenantAwareUsername = "testuser@testdomain";
        realmService = mock(RealmService.class);
        userRealm = mock(UserRealm.class);
        Mockito.when(authenticatedUser.toFullQualifiedUsername()).thenReturn(username);
        mockedMultitenantUtils.when(() -> MultitenantUtils.getTenantAwareUsername(username))
                .thenReturn(tenantAwareUsername);
        mockedMultitenantUtils.when(() -> MultitenantUtils.getTenantDomain(username)).thenReturn("testdomain");
        mockedIdentityTenantUtil.when(() -> IdentityTenantUtil.getTenantId("testdomain")).thenReturn(1);
        mockedIdentityTenantUtil.when(IdentityTenantUtil::getRealmService).thenReturn(realmService);
        Mockito.when(realmService.getTenantUserRealm(1)).thenReturn(userRealm);
        Mockito.when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);

        Map<String, String> claimValues = new HashMap<>();
        claimValues.put(VoiceOTPConstants.ACCOUNT_UNLOCK_TIME_CLAIM, "123456789");
        Mockito.when(userStoreManager.getUserClaimValues(tenantAwareUsername,
                new String[]{VoiceOTPConstants.ACCOUNT_UNLOCK_TIME_CLAIM},
                null)).thenReturn(claimValues);

        long unlockTime = (long) invokegetUnlockTimeInMilliSecondsPrivateMethodWithReturn(
                authenticator, "getUnlockTimeInMilliSeconds", authenticatedUser);
        Assert.assertEquals(123456789L, unlockTime);
    }

    private Object invokegetUnlockTimeInMilliSecondsPrivateMethodWithReturn(Object instance, String methodName,
            Object... args) throws Exception {
        Method method = instance.getClass().getDeclaredMethod(methodName, AuthenticatedUser.class);
        method.setAccessible(true);
        return method.invoke(instance, args);
    }

    @Test(expectedExceptions = Exception.class)
    public void testProcessValidUserTokenFail() throws Exception {
        doReturn(6).when(context).getProperty(VoiceOTPConstants.TOKEN_VALIDITY_TIME);
        doReturn(otpTime).when(context).getProperty(VoiceOTPConstants.SENT_OTP_TOKEN_TIME);

        invokeProcessValidUserTokenPrivateMethod(authenticator, "processValidUserToken", context, authenticatedUser);
    }

    @Test
    public void testProcessValidUserTokenSuccess() throws Exception {
        doReturn(System.currentTimeMillis()).when(context).getProperty(VoiceOTPConstants.TOKEN_VALIDITY_TIME);
        doReturn(otpTime).when(context).getProperty(VoiceOTPConstants.SENT_OTP_TOKEN_TIME);

        invokeProcessValidUserTokenPrivateMethod(authenticator, "processValidUserToken", context, authenticatedUser);
    }

    private void invokeProcessValidUserTokenPrivateMethod(Object instance, String methodName, Object... args)
            throws Exception {
        Method method = instance.getClass().getDeclaredMethod(methodName, AuthenticationContext.class,
                AuthenticatedUser.class);
        method.setAccessible(true);
        method.invoke(instance, args);
    }

    private static Object invokePrivateMethod(Object target, String methodName, Object... args) throws Exception {
        Class<?> clazz = target.getClass();
        while (clazz != null) {
            for (Method method : clazz.getDeclaredMethods()) {
                if (method.getName().equals(methodName) && method.getParameterCount() == args.length) {
                    method.setAccessible(true);
                    try {
                        return method.invoke(target, args);
                    } catch (java.lang.reflect.InvocationTargetException e) {
                        Throwable cause = e.getCause();
                        if (cause instanceof Exception) throw (Exception) cause;
                        throw new RuntimeException(cause);
                    }
                }
            }
            clazz = clazz.getSuperclass();
        }
        throw new NoSuchMethodException("Method " + methodName + " not found with " + args.length + " params");
    }

    private static Object invokePrivateMethod(Object target, String methodName, Class<?>[] paramTypes, Object... args)
            throws Exception {
        Class<?> clazz = target.getClass();
        while (clazz != null) {
            try {
                Method method = clazz.getDeclaredMethod(methodName, paramTypes);
                method.setAccessible(true);
                try {
                    return method.invoke(target, args);
                } catch (java.lang.reflect.InvocationTargetException e) {
                    Throwable cause = e.getCause();
                    if (cause instanceof Exception) throw (Exception) cause;
                    throw new RuntimeException(cause);
                }
            } catch (NoSuchMethodException e) {
                clazz = clazz.getSuperclass();
            }
        }
        throw new NoSuchMethodException("Method " + methodName + " not found");
    }
}

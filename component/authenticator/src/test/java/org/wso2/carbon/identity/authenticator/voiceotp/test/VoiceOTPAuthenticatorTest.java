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

import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Spy;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.powermock.reflect.Whitebox;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.ObjectFactory;
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
import org.wso2.carbon.identity.authenticator.voiceotp.VoiceOTPAuthenticator;
import org.wso2.carbon.identity.authenticator.voiceotp.VoiceOTPConstants;
import org.wso2.carbon.identity.authenticator.voiceotp.VoiceOTPUtils;
import org.wso2.carbon.identity.authenticator.voiceotp.exception.VoiceOTPException;
import org.wso2.carbon.identity.authenticator.voiceotp.internal.VoiceOTPServiceDataHolder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.user.api.Claim;
import org.wso2.carbon.user.api.ClaimManager;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.wso2.carbon.identity.authenticator.voiceotp.VoiceOTPConstants.REQUESTED_USER_MOBILE;

@RunWith(PowerMockRunner.class)
@PrepareForTest({ConfigurationFacade.class, VoiceOTPUtils.class, FederatedAuthenticatorUtil.class, FrameworkUtils.class,
        IdentityTenantUtil.class, VoiceOTPServiceDataHolder.class})
@PowerMockIgnore({"org.wso2.carbon.identity.application.common.model.User", "org.mockito.*", "javax.servlet.*"})
public class VoiceOTPAuthenticatorTest {
    
    private static final long otpTime = 1608101321322l;
    
    private VoiceOTPAuthenticator voiceotpAuthenticator;

    @Mock
    private HttpServletRequest httpServletRequest;

    @Mock
    private HttpServletResponse httpServletResponse;

    @Spy
    private AuthenticationContext context;

    @Spy
    private VoiceOTPAuthenticator spy;

    @Mock
    VoiceOTPUtils voiceotpUtils;

    @Mock
    private ConfigurationFacade configurationFacade;

    @Mock
    private UserStoreManager userStoreManager;

    @Mock
    private UserRealm userRealm;

    @Mock
    private RealmService realmService;

    @Mock private ClaimManager claimManager;
    @Mock private Claim claim;
    @Mock private VoiceOTPServiceDataHolder VoiceOTPServiceDataHolder;
    @Mock private IdentityEventService identityEventService;
    @Mock private Enumeration<String> requestHeaders;
    @Mock private AuthenticatedUser authenticatedUser;

    @BeforeMethod
    public void setUp() throws Exception {
        voiceotpAuthenticator = new VoiceOTPAuthenticator();
        mockStatic(VoiceOTPServiceDataHolder.class);
        when(VoiceOTPServiceDataHolder.getInstance()).thenReturn(VoiceOTPServiceDataHolder);
        when(VoiceOTPServiceDataHolder.getIdentityEventService()).thenReturn(identityEventService);
        when(httpServletRequest.getHeaderNames()).thenReturn(requestHeaders);
        initMocks(this);
    }

    @AfterMethod
    public void tearDown() throws Exception {
    }


    @Test
    public void testGetFriendlyName() {
        Assert.assertEquals(voiceotpAuthenticator.getFriendlyName(), VoiceOTPConstants.AUTHENTICATOR_FRIENDLY_NAME);
    }

    @Test
    public void testGetName() {
        Assert.assertEquals(voiceotpAuthenticator.getName(), VoiceOTPConstants.AUTHENTICATOR_NAME);
    }

    @Test
    public void testRetryAuthenticationEnabled() throws Exception {
        VoiceOTPAuthenticator voiceotp = PowerMockito.spy(voiceotpAuthenticator);
        Assert.assertTrue((Boolean) Whitebox.invokeMethod(voiceotp, "retryAuthenticationEnabled"));
    }

    @Test
    public void testGetContextIdentifierPassed() {
        when(httpServletRequest.getParameter(FrameworkConstants.SESSION_DATA_KEY)).thenReturn
                ("0246893");
        Assert.assertEquals(voiceotpAuthenticator.getContextIdentifier(httpServletRequest), "0246893");
    }

    @Test
    public void testCanHandleTrue() {
        when(httpServletRequest.getParameter(VoiceOTPConstants.CODE)).thenReturn(null);
        when(httpServletRequest.getParameter(VoiceOTPConstants.RESEND)).thenReturn("resendCode");
        Assert.assertEquals(voiceotpAuthenticator.canHandle(httpServletRequest), true);
    }

    @Test
    public void testCanHandleFalse() {
        when(httpServletRequest.getParameter(VoiceOTPConstants.CODE)).thenReturn(null);
        when(httpServletRequest.getParameter(VoiceOTPConstants.RESEND)).thenReturn(null);
        when(httpServletRequest.getParameter(VoiceOTPConstants.MOBILE_NUMBER)).thenReturn(null);
        Assert.assertEquals(voiceotpAuthenticator.canHandle(httpServletRequest), false);
    }

    @Test
    public void testGetURL() throws Exception {
        VoiceOTPAuthenticator voiceotp = PowerMockito.spy(voiceotpAuthenticator);
        Assert.assertEquals(Whitebox.invokeMethod(voiceotp, "getURL",
                VoiceOTPConstants.LOGIN_PAGE, null),
                "authenticationendpoint/login.do?authenticators=VoiceOTP");
    }

    @Test
    public void testGetURLwithQueryParams() throws Exception {
        VoiceOTPAuthenticator voiceotp = PowerMockito.spy(voiceotpAuthenticator);
        Assert.assertEquals(Whitebox.invokeMethod(voiceotp, "getURL",
                VoiceOTPConstants.LOGIN_PAGE, "n=John&n=Susan"),
                "authenticationendpoint/login.do?n=John&n=Susan&authenticators=VoiceOTP");
    }


    @Test
    public void testGetMobileNumber() throws Exception {
        mockStatic(VoiceOTPUtils.class);
        when(VoiceOTPUtils.getMobileNumberForUsername(anyString())).thenReturn("0775968325");
        Assert.assertEquals(Whitebox.invokeMethod(voiceotpAuthenticator, "getMobileNumber",
                httpServletRequest, httpServletResponse, any(AuthenticationContext.class),
                "Kanapriya", "queryParams"), "0775968325");
    }

    @Test
    public void testGetLoginPage() throws Exception {
        mockStatic(VoiceOTPUtils.class);
        mockStatic(ConfigurationFacade.class);
        when(ConfigurationFacade.getInstance()).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn("/authenticationendpoint/login.do");
        when(VoiceOTPUtils.getLoginPageFromXMLFile(any(AuthenticationContext.class))).thenReturn(null);
        Assert.assertNotEquals(Whitebox.invokeMethod(voiceotpAuthenticator, "getLoginPage",
                new AuthenticationContext()), "/authenticationendpoint/login.do");
        Assert.assertEquals(Whitebox.invokeMethod(voiceotpAuthenticator, "getLoginPage",
                new AuthenticationContext()), "/authenticationendpoint/voiceOtp.jsp");
    }

    @Test
    public void testGetErrorPage() throws Exception {
        mockStatic(VoiceOTPUtils.class);
        mockStatic(ConfigurationFacade.class);
        when(ConfigurationFacade.getInstance()).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn("/authenticationendpoint/login.do");
        when(VoiceOTPUtils.getErrorPageFromXMLFile(any(AuthenticationContext.class))).thenReturn(null);
        Assert.assertNotEquals(Whitebox.invokeMethod(voiceotpAuthenticator, "getErrorPage",
                new AuthenticationContext()), "/authenticationendpoint/login.do");
        Assert.assertEquals(Whitebox.invokeMethod(voiceotpAuthenticator, "getErrorPage",
                new AuthenticationContext()), "/authenticationendpoint/voiceOtpError.jsp");
    }

    @Test
    public void testRedirectToErrorPage() throws Exception {
        mockStatic(VoiceOTPUtils.class);
        AuthenticationContext authenticationContext = new AuthenticationContext();
        when(VoiceOTPUtils.getErrorPageFromXMLFile(authenticationContext))
                .thenReturn("/authenticationendpoint/voiceOtpError.jsp");
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(voiceotpAuthenticator, "redirectToErrorPage",
                httpServletResponse, authenticationContext, null, null);
        verify(httpServletResponse).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(VoiceOTPConstants.AUTHENTICATOR_NAME));
    }

    @Test
    public void testRedirectToMobileNumberReqPage() throws Exception {
        mockStatic(VoiceOTPUtils.class);
        AuthenticationContext authenticationContext = new AuthenticationContext();
        when(VoiceOTPUtils.isEnableMobileNoUpdate(authenticationContext)).thenReturn(true);
        when(VoiceOTPUtils.getMobileNumberRequestPage(authenticationContext))
                .thenReturn("/authenticationendpoint/mobile.jsp");
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(voiceotpAuthenticator, "redirectToMobileNoReqPage",
                httpServletResponse, authenticationContext, null);
        verify(httpServletResponse).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(VoiceOTPConstants.AUTHENTICATOR_NAME));
    }

    @Test
    public void testCheckStatusCode() throws Exception {
        mockStatic(VoiceOTPUtils.class);
        context.setProperty(VoiceOTPConstants.STATUS_CODE, "");
        when(VoiceOTPUtils.isRetryEnabled(context)).thenReturn(true);
        when(VoiceOTPUtils.getLoginPageFromXMLFile(any(AuthenticationContext.class))).
                thenReturn("/authenticationendpoint/voiceOtpError.jsp");
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(voiceotpAuthenticator, "checkStatusCode",
                httpServletResponse, context, null, VoiceOTPConstants.ERROR_PAGE);
        verify(httpServletResponse).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(VoiceOTPConstants.AUTHENTICATOR_NAME));
    }

    @Test
    public void testCheckStatusCodeWithNullValue() throws Exception {
        mockStatic(VoiceOTPUtils.class);
        context.setProperty(VoiceOTPConstants.STATUS_CODE, null);
        when(VoiceOTPUtils.isRetryEnabled(context)).thenReturn(true);
        when(VoiceOTPUtils.getLoginPageFromXMLFile(any(AuthenticationContext.class))).
                thenReturn("/authenticationendpoint/voiceOtp.jsp");
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(voiceotpAuthenticator, "checkStatusCode",
                httpServletResponse, context, null, VoiceOTPConstants.ERROR_PAGE);
        verify(httpServletResponse).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(VoiceOTPConstants.AUTHENTICATOR_NAME));
    }

    @Test
    public void testCheckStatusCodeWithMismatch() throws Exception {
        mockStatic(VoiceOTPUtils.class);
        context.setProperty(VoiceOTPConstants.CODE_MISMATCH, "true");
        when(VoiceOTPUtils.isRetryEnabled(context)).thenReturn(false);
        when(VoiceOTPUtils.isEnableResendCode(context)).thenReturn(true);
        when(VoiceOTPUtils.getLoginPageFromXMLFile(any(AuthenticationContext.class))).
                thenReturn("/authenticationendpoint/voiceOtpError.jsp");
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(voiceotpAuthenticator, "checkStatusCode",
                httpServletResponse, context, null, VoiceOTPConstants.ERROR_PAGE);
        verify(httpServletResponse).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(VoiceOTPConstants.ERROR_CODE_MISMATCH));
    }

    @Test
    public void testCheckStatusCodeWithTokenExpired() throws Exception {
        mockStatic(VoiceOTPUtils.class);
        context.setProperty(VoiceOTPConstants.TOKEN_EXPIRED, "token.expired");
        when(VoiceOTPUtils.isEnableResendCode(context)).thenReturn(true);
        when(VoiceOTPUtils.isRetryEnabled(context)).thenReturn(true);
        when(VoiceOTPUtils.getLoginPageFromXMLFile(any(AuthenticationContext.class))).
                thenReturn("/authenticationendpoint/voiceOtp.jsp");
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(voiceotpAuthenticator, "checkStatusCode",
                httpServletResponse, context, null, VoiceOTPConstants.VOICE_LOGIN_PAGE);
        verify(httpServletResponse).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(VoiceOTPConstants.TOKEN_EXPIRED_VALUE));
    }

    @Test
    public void testProcessVoiceOTPFlow() throws Exception {
        mockStatic(VoiceOTPUtils.class);
        when(VoiceOTPUtils.isVoiceOTPDisableForLocalUser("John", context)).thenReturn(true);
        when(VoiceOTPUtils.getErrorPageFromXMLFile(any(AuthenticationContext.class))).
                thenReturn(VoiceOTPConstants.ERROR_PAGE);
        when(VoiceOTPUtils.isEnableMobileNoUpdate(any(AuthenticationContext.class))).thenReturn(true);
        context.setProperty(VoiceOTPConstants.MOBILE_NUMBER_UPDATE_FAILURE, "true");
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(voiceotpAuthenticator, "processVoiceOTPFlow", context,
                httpServletRequest, httpServletResponse, true, "John@carbon.super", "", "carbon.super", VoiceOTPConstants
                        .ERROR_PAGE);
        verify(httpServletResponse).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(VoiceOTPConstants.AUTHENTICATOR_NAME));
    }

    @Test
    public void testSendOTPDirectlyToMobile() throws Exception {
        mockStatic(VoiceOTPUtils.class);
        when(VoiceOTPUtils.isSendOTPDirectlyToMobile(context)).thenReturn(true);
        when(VoiceOTPUtils.getMobileNumberRequestPage(any(AuthenticationContext.class))).
                thenReturn("/authenticationendpoint/mobile.jsp");
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(voiceotpAuthenticator, "processVoiceOTPFlow", context,
                httpServletRequest, httpServletResponse, false, "John@carbon.super", "", "carbon.super", VoiceOTPConstants
                        .ERROR_PAGE);
        verify(httpServletResponse).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(VoiceOTPConstants.AUTHENTICATOR_NAME));
    }

    @Test
    public void testProcessVoiceOTPDisableFlow() throws Exception {
        mockStatic(VoiceOTPUtils.class);
        when(VoiceOTPUtils.isSendOTPDirectlyToMobile(context)).thenReturn(false);
        when(VoiceOTPUtils.getErrorPageFromXMLFile(any(AuthenticationContext.class))).
                thenReturn(VoiceOTPConstants.ERROR_PAGE);
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(voiceotpAuthenticator, "processVoiceOTPFlow", context,
                httpServletRequest, httpServletResponse, false, "John@carbon.super", "", "carbon.super", VoiceOTPConstants
                        .ERROR_PAGE);
        verify(httpServletResponse).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(VoiceOTPConstants.SEND_OTP_DIRECTLY_DISABLE));
    }

    @Test
    public void testProcessWithLogoutTrue() throws AuthenticationFailedException, LogoutFailedException {
        when(context.isLogoutRequest()).thenReturn(true);
        AuthenticatorFlowStatus status = voiceotpAuthenticator.process(httpServletRequest, httpServletResponse, context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    @Test
    public void testProcessWithLogoutFalse() throws Exception {
        mockStatic(FederatedAuthenticatorUtil.class);
        mockStatic(VoiceOTPUtils.class);
        mockStatic(FrameworkUtils.class);
        when(context.isLogoutRequest()).thenReturn(false);
        when(httpServletRequest.getParameter(VoiceOTPConstants.MOBILE_NUMBER)).thenReturn("true");
        context.setTenantDomain("carbon.super");
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier("admin");
        when(context.getProperty(VoiceOTPConstants.OTP_GENERATED_TIME)).thenReturn(otpTime);
        when((AuthenticatedUser) context.getProperty(VoiceOTPConstants.AUTHENTICATED_USER)).thenReturn(authenticatedUser);
        FederatedAuthenticatorUtil.setUsernameFromFirstStep(context);
        when(VoiceOTPUtils.isVoiceOTPMandatory(context)).thenReturn(true);
        when(VoiceOTPUtils.getErrorPageFromXMLFile(context)).thenReturn(VoiceOTPConstants.ERROR_PAGE);
        when(VoiceOTPUtils.isSendOTPDirectlyToMobile(context)).thenReturn(false);
        when(FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier())).thenReturn(null);
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(voiceotpAuthenticator, "processVoiceOTPFlow", context,
                httpServletRequest, httpServletResponse, false, "John@carbon.super", "", "carbon.super", VoiceOTPConstants
                        .ERROR_PAGE);
        verify(httpServletResponse).sendRedirect(captor.capture());
        AuthenticatorFlowStatus status = spy.process(httpServletRequest, httpServletResponse, context);
        Assert.assertTrue(captor.getValue().contains(VoiceOTPConstants.SEND_OTP_DIRECTLY_DISABLE));
        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
    }

    @Test
    public void testProcessWithLogout() throws AuthenticationFailedException, LogoutFailedException {
        mockStatic(FederatedAuthenticatorUtil.class);
        mockStatic(VoiceOTPUtils.class);
        mockStatic(FrameworkUtils.class);
        when(context.isLogoutRequest()).thenReturn(false);
        when(httpServletRequest.getParameter(VoiceOTPConstants.CODE)).thenReturn("");
        context.setTenantDomain("carbon.super");
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier("admin");
        authenticatedUser.setUserName("testUser");
        authenticatedUser.setUserStoreDomain("secondary");
        context.setProperty(VoiceOTPConstants.SENT_OTP_TOKEN_TIME, otpTime);
        when((AuthenticatedUser) context.getProperty(VoiceOTPConstants.AUTHENTICATED_USER)).thenReturn(authenticatedUser);
        FederatedAuthenticatorUtil.setUsernameFromFirstStep(context);
        when(VoiceOTPUtils.isVoiceOTPMandatory(context)).thenReturn(true);
        when(VoiceOTPUtils.getErrorPageFromXMLFile(context)).thenReturn(VoiceOTPConstants.ERROR_PAGE);
        when(VoiceOTPUtils.isSendOTPDirectlyToMobile(context)).thenReturn(false);
        when(FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier())).thenReturn(null);
        when(VoiceOTPUtils.getBackupCode(context)).thenReturn("false");

        AuthenticatorFlowStatus status = spy.process(httpServletRequest, httpServletResponse, context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
    }

    @Test
    public void testInitiateAuthenticationRequestWithVoiceOTPMandatory() throws Exception {
        mockStatic(FederatedAuthenticatorUtil.class);
        mockStatic(VoiceOTPUtils.class);
        mockStatic(FrameworkUtils.class);
        context.setTenantDomain("carbon.super");
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier("admin");
        when((AuthenticatedUser) context.getProperty(VoiceOTPConstants.AUTHENTICATED_USER)).thenReturn(authenticatedUser);
        FederatedAuthenticatorUtil.setUsernameFromFirstStep(context);
        when(VoiceOTPUtils.isVoiceOTPMandatory(context)).thenReturn(true);
        when(VoiceOTPUtils.getErrorPageFromXMLFile(context)).thenReturn(VoiceOTPConstants.ERROR_PAGE);
        when(VoiceOTPUtils.isSendOTPDirectlyToMobile(context)).thenReturn(false);
        when(VoiceOTPUtils.getErrorPageFromXMLFile(any(AuthenticationContext.class))).
                thenReturn(VoiceOTPConstants.ERROR_PAGE);
        when(FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier())).thenReturn(null);
        when(VoiceOTPUtils.getBackupCode(context)).thenReturn("false");
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(voiceotpAuthenticator, "initiateAuthenticationRequest",
                httpServletRequest, httpServletResponse, context);
        verify(httpServletResponse).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(VoiceOTPConstants.SEND_OTP_DIRECTLY_DISABLE));
    }

    @Test
    public void testInitiateAuthenticationRequestWithVoiceOTPOptional() throws Exception {
        mockStatic(FederatedAuthenticatorUtil.class);
        mockStatic(VoiceOTPUtils.class);
        mockStatic(FrameworkUtils.class);
        context.setTenantDomain("carbon.super");
        context.setProperty(VoiceOTPConstants.TOKEN_EXPIRED, "token.expired");
        when(context.isRetrying()).thenReturn(true);
        when(httpServletRequest.getParameter(VoiceOTPConstants.RESEND)).thenReturn("false");
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier("admin");
        when((AuthenticatedUser) context.getProperty(VoiceOTPConstants.AUTHENTICATED_USER)).thenReturn(authenticatedUser);
        FederatedAuthenticatorUtil.setUsernameFromFirstStep(context);
        when(VoiceOTPUtils.isVoiceOTPMandatory(context)).thenReturn(false);
        when(VoiceOTPUtils.isRetryEnabled(context)).thenReturn(true);
        when(FederatedAuthenticatorUtil.isUserExistInUserStore(anyString())).thenReturn(true);
        when(VoiceOTPUtils.getMobileNumberForUsername(anyString())).thenReturn("0778965320");
        when(VoiceOTPUtils.getLoginPageFromXMLFile(any(AuthenticationContext.class))).
                thenReturn(VoiceOTPConstants.LOGIN_PAGE);
        when(VoiceOTPUtils.getErrorPageFromXMLFile(any(AuthenticationContext.class))).
                thenReturn(VoiceOTPConstants.ERROR_PAGE);
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(voiceotpAuthenticator, "initiateAuthenticationRequest",
                httpServletRequest, httpServletResponse, context);
        verify(httpServletResponse).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(VoiceOTPConstants.TOKEN_EXPIRED_VALUE));
    }

    @Test(expectedExceptions = {AuthenticationFailedException.class})
    public void testInitiateAuthenticationRequestWithoutAuthenticatedUser() throws Exception {
        mockStatic(FederatedAuthenticatorUtil.class);
        mockStatic(VoiceOTPUtils.class);
        mockStatic(FrameworkUtils.class);
        context.setTenantDomain("carbon.super");
        FederatedAuthenticatorUtil.setUsernameFromFirstStep(context);
        Whitebox.invokeMethod(voiceotpAuthenticator, "initiateAuthenticationRequest",
                httpServletRequest, httpServletResponse, context);
    }

    @Test(expectedExceptions = {InvalidCredentialsException.class})
    public void testProcessAuthenticationResponseWithoutOTPCode() throws Exception {

        mockStatic(VoiceOTPUtils.class);
        when(httpServletRequest.getParameter(VoiceOTPConstants.CODE)).thenReturn("");
        when(VoiceOTPUtils.isLocalUser(context)).thenReturn(true);
        Whitebox.invokeMethod(voiceotpAuthenticator, "processAuthenticationResponse",
                httpServletRequest, httpServletResponse, context);
    }

    @Test(expectedExceptions = {InvalidCredentialsException.class})
    public void testProcessAuthenticationResponseWithResend() throws Exception {

        mockStatic(VoiceOTPUtils.class);
        when(httpServletRequest.getParameter(VoiceOTPConstants.CODE)).thenReturn("123456");
        when(httpServletRequest.getParameter(VoiceOTPConstants.RESEND)).thenReturn("true");
        when(VoiceOTPUtils.isLocalUser(context)).thenReturn(true);
        Whitebox.invokeMethod(voiceotpAuthenticator, "processAuthenticationResponse",
                httpServletRequest, httpServletResponse, context);
    }

    @Test
    public void testProcessAuthenticationResponse() throws Exception {

        mockStatic(VoiceOTPUtils.class);
        mockStatic(IdentityTenantUtil.class);
        when(httpServletRequest.getParameter(VoiceOTPConstants.CODE)).thenReturn("123456");
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier("admin");
        authenticatedUser.setUserId("4b4414e1-916b-4475-aaee-6b0751c29ff6");
        authenticatedUser.setUserName("admin");
        authenticatedUser.setTenantDomain("carbon.super");
        StepConfig stepConfig = new StepConfig();
        stepConfig.setSubjectAttributeStep(true);
        stepConfig.setAuthenticatedUser(authenticatedUser);
        context.setProperty(VoiceOTPConstants.CODE_MISMATCH, false);
        context.setProperty(VoiceOTPConstants.OTP_TOKEN,"123456");
        context.setProperty(VoiceOTPConstants.TOKEN_VALIDITY_TIME,"");
        context.setSequenceConfig(new SequenceConfig());
        context.getSequenceConfig().getStepMap().put(1, stepConfig);
        Whitebox.invokeMethod(voiceotpAuthenticator, "getAuthenticatedUser",
                context);
        Property property = new Property();
        property.setName(VoiceOTPConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE);
        property.setValue("true");
        when(VoiceOTPUtils.getAccountLockConnectorConfigs(authenticatedUser.getTenantDomain()))
                .thenReturn(new Property[]{property});
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);

        Whitebox.invokeMethod(voiceotpAuthenticator, "processAuthenticationResponse",
                httpServletRequest, httpServletResponse, context);
    }

    @Test
    public void testProcessAuthenticationResponseWithvalidBackupCode() throws Exception {
        mockStatic(IdentityTenantUtil.class);
        mockStatic(VoiceOTPUtils.class);
        when(httpServletRequest.getParameter(VoiceOTPConstants.CODE)).thenReturn("123456");
        context.setProperty(VoiceOTPConstants.OTP_TOKEN,"123");
        context.setProperty(VoiceOTPConstants.USER_NAME,"admin");
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier("admin");
        authenticatedUser.setUserName("admin");
        when((AuthenticatedUser) context.getProperty(VoiceOTPConstants.AUTHENTICATED_USER)).thenReturn(authenticatedUser);
        when(VoiceOTPUtils.getBackupCode(context)).thenReturn("true");

        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager
                .getUserClaimValue("admin", VoiceOTPConstants.SAVED_OTP_LIST, null))
                .thenReturn("123456,789123");
        mockStatic(FrameworkUtils.class);
        when (FrameworkUtils.getMultiAttributeSeparator()).thenReturn(",");

        Property property = new Property();
        property.setName(VoiceOTPConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE);
        property.setValue("true");
        when(VoiceOTPUtils.getAccountLockConnectorConfigs(authenticatedUser.getTenantDomain()))
                .thenReturn(new Property[]{property});
        when(VoiceOTPUtils.isLocalUser(context)).thenReturn(true);
        when(userStoreManager.getClaimManager()).thenReturn(claimManager);
        when(userStoreManager.getClaimManager().getClaim(VoiceOTPConstants.SAVED_OTP_LIST)).thenReturn(claim);
        when(context.getProperty(VoiceOTPConstants.CODE_MISMATCH)).thenReturn(false);

        Whitebox.invokeMethod(voiceotpAuthenticator, "processAuthenticationResponse",
                httpServletRequest, httpServletResponse, context);
    }

    @Test(expectedExceptions = {AuthenticationFailedException.class})
    public void testProcessAuthenticationResponseWithCodeMismatch() throws Exception {
        mockStatic(VoiceOTPUtils.class);
        mockStatic(IdentityTenantUtil.class);
        when(httpServletRequest.getParameter(VoiceOTPConstants.CODE)).thenReturn("123456");
        context.setProperty(VoiceOTPConstants.OTP_TOKEN,"123");
        context.setProperty(VoiceOTPConstants.USER_NAME,"admin");
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier("admin");
        authenticatedUser.setTenantDomain("carbon.super");
        when((AuthenticatedUser) context.getProperty(VoiceOTPConstants.AUTHENTICATED_USER)).thenReturn(authenticatedUser);
        when(VoiceOTPUtils.getBackupCode(context)).thenReturn("false");

        Property property = new Property();
        property.setName(VoiceOTPConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE);
        property.setValue("true");
        when(VoiceOTPUtils.getAccountLockConnectorConfigs(authenticatedUser.getTenantDomain()))
                .thenReturn(new Property[]{property});

        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);

        Whitebox.invokeMethod(voiceotpAuthenticator, "processAuthenticationResponse",
                httpServletRequest, httpServletResponse, context);
    }

    @Test
    public void testCheckWithBackUpCodes() throws Exception {
        mockStatic(IdentityTenantUtil.class);
        context.setProperty(VoiceOTPConstants.USER_NAME,"admin");
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier("admin");
        when((AuthenticatedUser) context.getProperty(VoiceOTPConstants.AUTHENTICATED_USER)).thenReturn(authenticatedUser);
        when(userRealm.getUserStoreManager()
                .getUserClaimValue(MultitenantUtils.getTenantAwareUsername("admin"),
                        VoiceOTPConstants.SAVED_OTP_LIST, null)).thenReturn("12345,4568,1234,7896");
        AuthenticatedUser user = (AuthenticatedUser) context.getProperty(VoiceOTPConstants.AUTHENTICATED_USER);
        mockStatic(FrameworkUtils.class);
        when (FrameworkUtils.getMultiAttributeSeparator()).thenReturn(",");
        Whitebox.invokeMethod(voiceotpAuthenticator, "checkWithBackUpCodes",
                context,"1234",user);
    }

    public void testCheckWithInvalidBackUpCodes() throws Exception {

        mockStatic(IdentityTenantUtil.class);
        mockStatic(VoiceOTPUtils.class);
        context.setProperty(VoiceOTPConstants.USER_NAME,"admin");
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier("admin");
        when((AuthenticatedUser) context.getProperty(VoiceOTPConstants.AUTHENTICATED_USER)).thenReturn(authenticatedUser);
        mockStatic(FrameworkUtils.class);
        when (FrameworkUtils.getMultiAttributeSeparator()).thenReturn(",");
        when(userRealm.getUserStoreManager()
                .getUserClaimValue(MultitenantUtils.getTenantAwareUsername("admin"),
                        VoiceOTPConstants.SAVED_OTP_LIST, null)).thenReturn("12345,4568,1234,7896");
        Whitebox.invokeMethod(voiceotpAuthenticator, "checkWithBackUpCodes",
                context, "45698789", authenticatedUser);
    }

    @Test
    public void testGetScreenAttribute() throws UserStoreException, AuthenticationFailedException {
        mockStatic(IdentityTenantUtil.class);
        mockStatic(VoiceOTPUtils.class);
        when(VoiceOTPUtils.getScreenUserAttribute(context)).thenReturn
                ("http://wso2.org/claims/mobile");
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userRealm.getUserStoreManager()
                .getUserClaimValue("admin", "http://wso2.org/claims/mobile", null)).thenReturn("0778965231");
        when(VoiceOTPUtils.getNoOfDigits(context)).thenReturn("4");

        // with forward order
        Assert.assertEquals(voiceotpAuthenticator.getScreenAttribute(context,userRealm,"admin"),"0778******");

        // with backward order
        when(VoiceOTPUtils.getDigitsOrder(context)).thenReturn("backward");
        Assert.assertEquals(voiceotpAuthenticator.getScreenAttribute(context,userRealm,"admin"),"******5231");
    }

    @Test
    public void testGetScreenAttributeWhenMobileRequest() throws UserStoreException {

        mockStatic(IdentityTenantUtil.class);
        mockStatic(VoiceOTPUtils.class);
        when(VoiceOTPUtils.getScreenUserAttribute(context)).thenReturn
                ("http://wso2.org/claims/mobile");
        when(context.getProperty(REQUESTED_USER_MOBILE)).thenReturn("0778899889");
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userRealm.getUserStoreManager()
                .getUserClaimValue("admin", "http://wso2.org/claims/mobile", null)).thenReturn(null);
        when(VoiceOTPUtils.getNoOfDigits(context)).thenReturn("4");

        // with forward order
        Assert.assertEquals(voiceotpAuthenticator.getScreenAttribute(context, userRealm, "admin"), "0778******");

        // with backward order
        when(VoiceOTPUtils.getDigitsOrder(context)).thenReturn("backward");
        Assert.assertEquals(voiceotpAuthenticator.getScreenAttribute(context, userRealm, "admin"), "******9889");
    }

    @Test(expectedExceptions = {VoiceOTPException.class})
    public void testUpdateMobileNumberForUsername() throws Exception {
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(null);
        Whitebox.invokeMethod(voiceotpAuthenticator, "updateMobileNumberForUsername",
                context,httpServletRequest,"admin","carbon.super");
    }

    @Test
    public void testGetConfigurationProperties() {
        List<Property> configProperties = new ArrayList<Property>();
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
        Assert.assertEquals(configProperties.size(), voiceotpAuthenticator.getConfigurationProperties().size());
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new PowerMockObjectFactory();
    }
}
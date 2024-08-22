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
import org.junit.runner.RunWith;
import org.mockito.Spy;
import org.mockito.Mock;
import org.mockito.InjectMocks;
import org.mockito.Mockito;
import org.mockito.ArgumentCaptor;
import org.owasp.encoder.Encode;
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

import javax.crypto.Mac;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyObject;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.wso2.carbon.identity.authenticator.voiceotp.VoiceOTPConstants.REQUESTED_USER_MOBILE;
import static org.wso2.carbon.identity.authenticator.voiceotp.VoiceOTPConstants.DIVISOR;
import static org.wso2.carbon.identity.authenticator.voiceotp.VoiceOTPConstants.OTP_SEPARATOR;
import static org.wso2.carbon.identity.authenticator.voiceotp.VoiceOTPConstants.POST_METHOD;

@RunWith(PowerMockRunner.class)
@PrepareForTest({ConfigurationFacade.class, VoiceOTPUtils.class, FederatedAuthenticatorUtil.class, FrameworkUtils.class,
        IdentityTenantUtil.class, VoiceOTPServiceDataHolder.class,MultitenantUtils.class,URL.class,
        OneTimePasswordUtils.class,Mac.class,UserStoreManager.class})
@PowerMockIgnore({"org.wso2.carbon.identity.application.common.model.User", "org.mockito.*", "javax.servlet.*",
        "javax.net.ssl.*", "sun.net.www.protocol.https.*"})
public class VoiceOTPAuthenticatorTest {

    private static final long otpTime = 1608101321322l;
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
    @Mock private ClaimManager claimManager;
    @Mock private Claim claim;
    @Mock private AuthenticatedUser authenticatedUser;
    @Mock private Map<String, String> authenticatorProperties;
    @Mock private HttpURLConnection httpURLConnection;
    @InjectMocks
    private VoiceOTPAuthenticator authenticator = new VoiceOTPAuthenticator();

    @BeforeMethod
    public void setUp() {

        initMocks(this);
        PowerMockito.mockStatic(MultitenantUtils.class);
        PowerMockito.mockStatic(VoiceOTPUtils.class);
        PowerMockito.mockStatic(OneTimePasswordUtils.class);
        PowerMockito.mockStatic(FederatedAuthenticatorUtil.class);
        PowerMockito.mockStatic(IdentityTenantUtil.class);

    }

    @AfterMethod
    public void tearDown() throws Exception {
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
        
        VoiceOTPAuthenticator voiceotp = PowerMockito.spy(authenticator);
        Assert.assertTrue((Boolean) Whitebox.invokeMethod(voiceotp, "retryAuthenticationEnabled"));
    }

    @Test
    public void testGetContextIdentifierPassed() {
        
        PowerMockito.when(httpServletRequest.getParameter(FrameworkConstants.SESSION_DATA_KEY)).thenReturn
                ("0246893");
        Assert.assertEquals(authenticator.getContextIdentifier(httpServletRequest), "0246893");
    }

    @Test
    public void testCanHandleTrue() {
        
        PowerMockito.when(httpServletRequest.getParameter(VoiceOTPConstants.CODE)).thenReturn(null);
        PowerMockito.when(httpServletRequest.getParameter(VoiceOTPConstants.RESEND)).thenReturn("resendCode");
        Assert.assertEquals(authenticator.canHandle(httpServletRequest), true);
    }

    @Test
    public void testCanHandleFalse() {
        
        PowerMockito.when(httpServletRequest.getParameter(VoiceOTPConstants.CODE)).thenReturn(null);
        PowerMockito.when(httpServletRequest.getParameter(VoiceOTPConstants.RESEND)).thenReturn(null);
        PowerMockito.when(httpServletRequest.getParameter(VoiceOTPConstants.MOBILE_NUMBER)).thenReturn(null);
        Assert.assertEquals(authenticator.canHandle(httpServletRequest), false);
    }

    @Test
    public void testGetURL() throws Exception {
        
        VoiceOTPAuthenticator voiceotp = PowerMockito.spy(authenticator);
        Assert.assertEquals(Whitebox.invokeMethod(voiceotp, "getURL",
                VoiceOTPConstants.LOGIN_PAGE, null),
                "authenticationendpoint/login.do?authenticators=VoiceOTP");
    }

    @Test
    public void testGetURLwithQueryParams() throws Exception {
        
        VoiceOTPAuthenticator voiceotp = PowerMockito.spy(authenticator);
        Assert.assertEquals(Whitebox.invokeMethod(voiceotp, "getURL",
                VoiceOTPConstants.LOGIN_PAGE, "n=John&n=Susan"),
                "authenticationendpoint/login.do?n=John&n=Susan&authenticators=VoiceOTP");
    }


    @Test
    public void testGetMobileNumber() throws Exception {
        
        mockStatic(VoiceOTPUtils.class);
        PowerMockito.when(VoiceOTPUtils.getMobileNumberForUsername(anyString())).thenReturn("0775968325");
        Assert.assertEquals(Whitebox.invokeMethod(authenticator, "getMobileNumber",
                httpServletRequest, response, any(AuthenticationContext.class),
                "Kanapriya", "queryParams"), "0775968325");
    }

    @Test
    public void testGetLoginPage() throws Exception {
        
        mockStatic(VoiceOTPUtils.class);
        mockStatic(ConfigurationFacade.class);
        PowerMockito.when(ConfigurationFacade.getInstance()).thenReturn(configurationFacade);
        PowerMockito.when(configurationFacade.getAuthenticationEndpointURL())
                .thenReturn("/authenticationendpoint/login.do");
        PowerMockito.when(VoiceOTPUtils.getLoginPageFromXMLFile(any(AuthenticationContext.class))).thenReturn(null);
        Assert.assertNotEquals(Whitebox.invokeMethod(authenticator, "getLoginPage",
                new AuthenticationContext()), "/authenticationendpoint/login.do");
        Assert.assertEquals(Whitebox.invokeMethod(authenticator, "getLoginPage",
                new AuthenticationContext()), "/authenticationendpoint/voiceOtp.jsp");
    }

    @Test
    public void testGetErrorPage() throws Exception {
        
        mockStatic(VoiceOTPUtils.class);
        mockStatic(ConfigurationFacade.class);
        PowerMockito.when(ConfigurationFacade.getInstance()).thenReturn(configurationFacade);
        PowerMockito.when(configurationFacade.getAuthenticationEndpointURL())
                .thenReturn("/authenticationendpoint/login.do");
        PowerMockito.when(VoiceOTPUtils.getErrorPageFromXMLFile(any(AuthenticationContext.class))).thenReturn(null);
        Assert.assertNotEquals(Whitebox.invokeMethod(authenticator, "getErrorPage",
                new AuthenticationContext()), "/authenticationendpoint/login.do");
        Assert.assertEquals(Whitebox.invokeMethod(authenticator, "getErrorPage",
                new AuthenticationContext()), "/authenticationendpoint/voiceOtpError.jsp");
    }

    @Test
    public void testRedirectToErrorPage() throws Exception {
        
        mockStatic(VoiceOTPUtils.class);
        AuthenticationContext authenticationContext = new AuthenticationContext();
        PowerMockito.when(VoiceOTPUtils.getErrorPageFromXMLFile(authenticationContext))
                .thenReturn("/authenticationendpoint/voiceOtpError.jsp");
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(authenticator, "redirectToErrorPage",
                response, authenticationContext, null, null);
        verify(response).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(VoiceOTPConstants.AUTHENTICATOR_NAME));
    }

    @Test
    public void testRedirectToMobileNumberReqPage() throws Exception {
        
        mockStatic(VoiceOTPUtils.class);
        AuthenticationContext authenticationContext = new AuthenticationContext();
        PowerMockito.when(VoiceOTPUtils.isEnableMobileNoUpdate(authenticationContext)).thenReturn(true);
        PowerMockito.when(VoiceOTPUtils.getMobileNumberRequestPage(authenticationContext))
                .thenReturn("/authenticationendpoint/mobile.jsp");
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(authenticator, "redirectToMobileNoReqPage",
                response, authenticationContext, null);
        verify(response).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(VoiceOTPConstants.AUTHENTICATOR_NAME));
    }

    @Test
    public void testCheckStatusCode() throws Exception {
        
        mockStatic(VoiceOTPUtils.class);
        context.setProperty(VoiceOTPConstants.STATUS_CODE, "");
        PowerMockito.when(VoiceOTPUtils.isRetryEnabled(context)).thenReturn(true);
        PowerMockito.when(VoiceOTPUtils.getLoginPageFromXMLFile(any(AuthenticationContext.class))).
                thenReturn("/authenticationendpoint/voiceOtpError.jsp");
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(authenticator, "checkStatusCode",
                response, context, null, VoiceOTPConstants.ERROR_PAGE);
        verify(response).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(VoiceOTPConstants.AUTHENTICATOR_NAME));
    }

    @Test
    public void testCheckStatusCodeWithNullValue() throws Exception {
        
        mockStatic(VoiceOTPUtils.class);
        context.setProperty(VoiceOTPConstants.STATUS_CODE, null);
        PowerMockito.when(VoiceOTPUtils.isRetryEnabled(context)).thenReturn(true);
        PowerMockito.when(VoiceOTPUtils.getLoginPageFromXMLFile(any(AuthenticationContext.class))).
                thenReturn("/authenticationendpoint/voiceOtp.jsp");
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(authenticator, "checkStatusCode",
                response, context, null, VoiceOTPConstants.ERROR_PAGE);
        verify(response).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(VoiceOTPConstants.AUTHENTICATOR_NAME));
    }

    @Test
    public void testCheckStatusCodeWithMismatch() throws Exception {
        
        mockStatic(VoiceOTPUtils.class);
        context.setProperty(VoiceOTPConstants.CODE_MISMATCH, "true");
        PowerMockito.when(VoiceOTPUtils.isRetryEnabled(context)).thenReturn(false);
        PowerMockito.when(VoiceOTPUtils.isEnableResendCode(context)).thenReturn(true);
        PowerMockito.when(VoiceOTPUtils.getLoginPageFromXMLFile(any(AuthenticationContext.class))).
                thenReturn("/authenticationendpoint/voiceOtpError.jsp");
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(authenticator, "checkStatusCode",
                response, context, null, VoiceOTPConstants.ERROR_PAGE);
        verify(response).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(VoiceOTPConstants.ERROR_CODE_MISMATCH));
    }

    @Test
    public void testCheckStatusCodeWithTokenExpired() throws Exception {
        
        mockStatic(VoiceOTPUtils.class);
        context.setProperty(VoiceOTPConstants.TOKEN_EXPIRED, "token.expired");
        PowerMockito.when(VoiceOTPUtils.isEnableResendCode(context)).thenReturn(true);
        PowerMockito.when(VoiceOTPUtils.isRetryEnabled(context)).thenReturn(true);
        PowerMockito.when(VoiceOTPUtils.getLoginPageFromXMLFile(any(AuthenticationContext.class))).
                thenReturn("/authenticationendpoint/voiceOtp.jsp");
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(authenticator, "checkStatusCode",
                response, context, null, VoiceOTPConstants.VOICE_LOGIN_PAGE);
        verify(response).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(VoiceOTPConstants.TOKEN_EXPIRED_VALUE));
    }

    @Test
    public void testProcessVoiceOTPFlow() throws Exception {
        
        mockStatic(VoiceOTPUtils.class);
        PowerMockito.when(VoiceOTPUtils.isVoiceOTPDisableForLocalUser("John", context)).thenReturn(true);
        PowerMockito.when(VoiceOTPUtils.getErrorPageFromXMLFile(any(AuthenticationContext.class))).
                thenReturn(VoiceOTPConstants.ERROR_PAGE);
        PowerMockito.when(VoiceOTPUtils.isEnableMobileNoUpdate(any(AuthenticationContext.class))).thenReturn(true);
        context.setProperty(VoiceOTPConstants.MOBILE_NUMBER_UPDATE_FAILURE, "true");
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(authenticator, "processVoiceOTPFlow", context,
                httpServletRequest, response, true, "John@carbon.super", "", "carbon.super", VoiceOTPConstants
                        .ERROR_PAGE);
        verify(response).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(VoiceOTPConstants.AUTHENTICATOR_NAME));
    }

    @Test
    public void testSendOTPDirectlyToMobile() throws Exception {
        
        mockStatic(VoiceOTPUtils.class);
        PowerMockito.when(VoiceOTPUtils.isSendOTPDirectlyToMobile(context)).thenReturn(true);
        PowerMockito.when(VoiceOTPUtils.getMobileNumberRequestPage(any(AuthenticationContext.class))).
                thenReturn("/authenticationendpoint/mobile.jsp");
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(authenticator, "processVoiceOTPFlow", context,
                httpServletRequest, response, false, "John@carbon.super", "", "carbon.super", VoiceOTPConstants
                        .ERROR_PAGE);
        verify(response).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(VoiceOTPConstants.AUTHENTICATOR_NAME));
    }

    @Test
    public void testProcessVoiceOTPDisableFlow() throws Exception {
        
        mockStatic(VoiceOTPUtils.class);
        PowerMockito.when(VoiceOTPUtils.isSendOTPDirectlyToMobile(context)).thenReturn(false);
        PowerMockito.when(VoiceOTPUtils.getErrorPageFromXMLFile(any(AuthenticationContext.class))).
                thenReturn(VoiceOTPConstants.ERROR_PAGE);
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(authenticator, "processVoiceOTPFlow", context,
                httpServletRequest, response, false, "John@carbon.super", "", "carbon.super", VoiceOTPConstants
                        .ERROR_PAGE);
        verify(response).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(VoiceOTPConstants.SEND_OTP_DIRECTLY_DISABLE));
    }

    @Test
    public void testProcessWithLogoutTrue() throws AuthenticationFailedException, LogoutFailedException {
        
        PowerMockito.when(context.isLogoutRequest()).thenReturn(true);
        AuthenticatorFlowStatus status = authenticator.process(httpServletRequest, response, context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    @Test
    public void testProcessWithLogoutFalse() throws Exception {
        
        mockStatic(FederatedAuthenticatorUtil.class);
        mockStatic(VoiceOTPUtils.class);
        mockStatic(FrameworkUtils.class);
        PowerMockito.when(context.isLogoutRequest()).thenReturn(false);
        PowerMockito.when(httpServletRequest.getParameter(VoiceOTPConstants.MOBILE_NUMBER)).thenReturn("true");
        context.setTenantDomain("carbon.super");
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier("admin");
        PowerMockito.when(context.getProperty(VoiceOTPConstants.OTP_GENERATED_TIME)).thenReturn(otpTime);
        PowerMockito.when((AuthenticatedUser) context.getProperty(VoiceOTPConstants.AUTHENTICATED_USER))
                .thenReturn(authenticatedUser);
        FederatedAuthenticatorUtil.setUsernameFromFirstStep(context);
        PowerMockito.when(VoiceOTPUtils.isVoiceOTPMandatory(context)).thenReturn(true);
        PowerMockito.when(VoiceOTPUtils.getErrorPageFromXMLFile(context)).thenReturn(VoiceOTPConstants.ERROR_PAGE);
        PowerMockito.when(VoiceOTPUtils.isSendOTPDirectlyToMobile(context)).thenReturn(false);
        PowerMockito.when(FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier())).thenReturn(null);
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(authenticator, "processVoiceOTPFlow", context,
                httpServletRequest, response, false, "John@carbon.super", "", "carbon.super", VoiceOTPConstants
                        .ERROR_PAGE);
        verify(response).sendRedirect(captor.capture());
        AuthenticatorFlowStatus status = authenticator.process(httpServletRequest, response, context);
        Assert.assertTrue(captor.getValue().contains(VoiceOTPConstants.SEND_OTP_DIRECTLY_DISABLE));
        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
    }

    @Test
    public void testProcessWithLogout() throws AuthenticationFailedException, LogoutFailedException {
        
        mockStatic(FederatedAuthenticatorUtil.class);
        mockStatic(VoiceOTPUtils.class);
        mockStatic(FrameworkUtils.class);
        PowerMockito.when(context.isLogoutRequest()).thenReturn(false);
        PowerMockito.when(httpServletRequest.getParameter(VoiceOTPConstants.CODE)).thenReturn("");
        context.setTenantDomain("carbon.super");
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier("admin");
        authenticatedUser.setUserName("testUser");
        authenticatedUser.setUserStoreDomain("secondary");
        context.setProperty(VoiceOTPConstants.SENT_OTP_TOKEN_TIME, otpTime);
        PowerMockito.when((AuthenticatedUser) context.getProperty(VoiceOTPConstants.AUTHENTICATED_USER))
                .thenReturn(authenticatedUser);
        FederatedAuthenticatorUtil.setUsernameFromFirstStep(context);
        PowerMockito.when(VoiceOTPUtils.isVoiceOTPMandatory(context)).thenReturn(true);
        PowerMockito.when(VoiceOTPUtils.getErrorPageFromXMLFile(context)).thenReturn(VoiceOTPConstants.ERROR_PAGE);
        PowerMockito.when(VoiceOTPUtils.isSendOTPDirectlyToMobile(context)).thenReturn(false);
        PowerMockito.when(FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier())).thenReturn(null);
        PowerMockito.when(VoiceOTPUtils.getBackupCode(context)).thenReturn("false");

        AuthenticatorFlowStatus status = authenticator.process(httpServletRequest, response, context);
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
        PowerMockito.when((AuthenticatedUser) context.getProperty(VoiceOTPConstants.AUTHENTICATED_USER))
                .thenReturn(authenticatedUser);
        FederatedAuthenticatorUtil.setUsernameFromFirstStep(context);
        PowerMockito.when(VoiceOTPUtils.isVoiceOTPMandatory(context)).thenReturn(true);
        PowerMockito.when(VoiceOTPUtils.getErrorPageFromXMLFile(context)).thenReturn(VoiceOTPConstants.ERROR_PAGE);
        PowerMockito.when(VoiceOTPUtils.isSendOTPDirectlyToMobile(context)).thenReturn(false);
        PowerMockito.when(VoiceOTPUtils.getErrorPageFromXMLFile(any(AuthenticationContext.class))).
                thenReturn(VoiceOTPConstants.ERROR_PAGE);
        PowerMockito.when(FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier())).thenReturn(null);
        PowerMockito.when(VoiceOTPUtils.getBackupCode(context)).thenReturn("false");
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(authenticator, "initiateAuthenticationRequest",
                httpServletRequest, response, context);
        verify(response).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(VoiceOTPConstants.SEND_OTP_DIRECTLY_DISABLE));
    }

    @Test
    public void testInitiateAuthenticationRequestWithVoiceOTPOptional() throws Exception {
        
        mockStatic(FederatedAuthenticatorUtil.class);
        mockStatic(VoiceOTPUtils.class);
        mockStatic(FrameworkUtils.class);
        context.setTenantDomain("carbon.super");
        context.setProperty(VoiceOTPConstants.TOKEN_EXPIRED, "token.expired");
        PowerMockito.when(context.isRetrying()).thenReturn(true);
        PowerMockito.when(httpServletRequest.getParameter(VoiceOTPConstants.RESEND)).thenReturn("false");
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier("admin");
        PowerMockito.when((AuthenticatedUser) context.getProperty(VoiceOTPConstants.AUTHENTICATED_USER))
                .thenReturn(authenticatedUser);
        FederatedAuthenticatorUtil.setUsernameFromFirstStep(context);
        PowerMockito.when(VoiceOTPUtils.isVoiceOTPMandatory(context)).thenReturn(false);
        PowerMockito.when(VoiceOTPUtils.isRetryEnabled(context)).thenReturn(true);
        PowerMockito.when(FederatedAuthenticatorUtil.isUserExistInUserStore(anyString())).thenReturn(true);
        PowerMockito.when(VoiceOTPUtils.getMobileNumberForUsername(anyString())).thenReturn("0778965320");
        PowerMockito.when(VoiceOTPUtils.getLoginPageFromXMLFile(any(AuthenticationContext.class))).
                thenReturn(VoiceOTPConstants.LOGIN_PAGE);
        PowerMockito.when(VoiceOTPUtils.getErrorPageFromXMLFile(any(AuthenticationContext.class))).
                thenReturn(VoiceOTPConstants.ERROR_PAGE);
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(authenticator, "initiateAuthenticationRequest",
                httpServletRequest, response, context);
        verify(response).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(VoiceOTPConstants.TOKEN_EXPIRED_VALUE));
    }

    @Test(expectedExceptions = {AuthenticationFailedException.class})
    public void testInitiateAuthenticationRequestWithoutAuthenticatedUser() throws Exception {
        
        mockStatic(FederatedAuthenticatorUtil.class);
        mockStatic(VoiceOTPUtils.class);
        mockStatic(FrameworkUtils.class);
        context.setTenantDomain("carbon.super");
        FederatedAuthenticatorUtil.setUsernameFromFirstStep(context);
        Whitebox.invokeMethod(authenticator, "initiateAuthenticationRequest",
                httpServletRequest, response, context);
    }

    @Test(expectedExceptions = {InvalidCredentialsException.class})
    public void testProcessAuthenticationResponseWithoutOTPCode() throws Exception {

        mockStatic(VoiceOTPUtils.class);
        PowerMockito.when(httpServletRequest.getParameter(VoiceOTPConstants.CODE)).thenReturn("");
        PowerMockito.when(VoiceOTPUtils.isLocalUser(context)).thenReturn(true);
        Whitebox.invokeMethod(authenticator, "processAuthenticationResponse",
                httpServletRequest, response, context);
    }

    @Test(expectedExceptions = {InvalidCredentialsException.class})
    public void testProcessAuthenticationResponseWithResend() throws Exception {

        mockStatic(VoiceOTPUtils.class);
        PowerMockito.when(httpServletRequest.getParameter(VoiceOTPConstants.CODE)).thenReturn("123456");
        PowerMockito.when(httpServletRequest.getParameter(VoiceOTPConstants.RESEND)).thenReturn("true");
        PowerMockito.when(VoiceOTPUtils.isLocalUser(context)).thenReturn(true);
        Whitebox.invokeMethod(authenticator, "processAuthenticationResponse",
                httpServletRequest, response, context);
    }

    @Test
    public void testProcessAuthenticationResponse() throws Exception {

        mockStatic(VoiceOTPUtils.class);
        mockStatic(IdentityTenantUtil.class);
        PowerMockito.when(httpServletRequest.getParameter(VoiceOTPConstants.CODE)).thenReturn("123456");
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
        Whitebox.invokeMethod(authenticator, "getAuthenticatedUser",
                context);
        Property property = new Property();
        property.setName(VoiceOTPConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE);
        property.setValue("true");
        PowerMockito.when(VoiceOTPUtils.getAccountLockConnectorConfigs(authenticatedUser.getTenantDomain()))
                .thenReturn(new Property[]{property});
        PowerMockito.when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        PowerMockito.when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        PowerMockito.when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        PowerMockito.when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);

        Whitebox.invokeMethod(authenticator, "processAuthenticationResponse",
                httpServletRequest, response, context);
    }

    @Test
    public void testProcessAuthenticationResponseWithvalidBackupCode() throws Exception {
        
        mockStatic(IdentityTenantUtil.class);
        mockStatic(VoiceOTPUtils.class);
        PowerMockito.when(httpServletRequest.getParameter(VoiceOTPConstants.CODE)).thenReturn("123456");
        context.setProperty(VoiceOTPConstants.OTP_TOKEN,"123456");
        context.setProperty(VoiceOTPConstants.USER_NAME,"admin");
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier("admin");
        authenticatedUser.setUserName("admin");
        PowerMockito.when((AuthenticatedUser) context.getProperty(VoiceOTPConstants.AUTHENTICATED_USER))
                .thenReturn(authenticatedUser);
        PowerMockito.when(VoiceOTPUtils.getBackupCode(context)).thenReturn("true");

        PowerMockito.when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        PowerMockito.when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        PowerMockito.when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        PowerMockito.when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        PowerMockito.when(userStoreManager
                .getUserClaimValue("admin@carbon.super", VoiceOTPConstants.SAVED_OTP_LIST, null))
                .thenReturn("123456,789123");
        mockStatic(FrameworkUtils.class);
        PowerMockito.when(FrameworkUtils.getMultiAttributeSeparator()).thenReturn(",");

        Property property = new Property();
        property.setName(VoiceOTPConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE);
        property.setValue("true");
        PowerMockito.when(VoiceOTPUtils.getAccountLockConnectorConfigs(authenticatedUser.getTenantDomain()))
                .thenReturn(new Property[]{property});
        PowerMockito.when(VoiceOTPUtils.isLocalUser(context)).thenReturn(true);
        PowerMockito.when(userStoreManager.getClaimManager()).thenReturn(claimManager);
        PowerMockito.when(userStoreManager.getClaimManager().getClaim(VoiceOTPConstants.SAVED_OTP_LIST))
                .thenReturn(claim);
        PowerMockito.when(context.getProperty(VoiceOTPConstants.CODE_MISMATCH)).thenReturn(false);

        SequenceConfig sequenceConfig = new SequenceConfig();
        Map<Integer, StepConfig> stepMap = new HashMap<>();

        StepConfig stepConfig = new StepConfig();
        stepConfig.setSubjectAttributeStep(true);

        AuthenticatedUser authUser = new AuthenticatedUser();
        stepConfig.setAuthenticatedUser(authUser);

        PowerMockito.when(VoiceOTPUtils.isAccountLocked(authenticatedUser)).thenReturn(false);

        stepMap.put(1,stepConfig);
        sequenceConfig.setStepMap(stepMap);

        PowerMockito.when(VoiceOTPUtils.isLocalUser(context)).thenReturn(true);
        PowerMockito.when(VoiceOTPUtils.getBackupCode(context)).thenReturn("true");

        PowerMockito.when(context.getSequenceConfig()).thenReturn(new SequenceConfig());

        Whitebox.invokeMethod(authenticator, "processAuthenticationResponse",
                httpServletRequest, response, context);
    }

    @Test(expectedExceptions = {AuthenticationFailedException.class})
    public void testProcessAuthenticationResponseWithCodeMismatch() throws Exception {
        
        mockStatic(VoiceOTPUtils.class);
        mockStatic(IdentityTenantUtil.class);
        PowerMockito.when(httpServletRequest.getParameter(VoiceOTPConstants.CODE)).thenReturn("123456");
        context.setProperty(VoiceOTPConstants.OTP_TOKEN,"123");
        context.setProperty(VoiceOTPConstants.USER_NAME,"admin");
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier("admin");
        authenticatedUser.setTenantDomain("carbon.super");
        PowerMockito.when((AuthenticatedUser) context.getProperty(VoiceOTPConstants.AUTHENTICATED_USER))
                .thenReturn(authenticatedUser);
        PowerMockito.when(VoiceOTPUtils.getBackupCode(context)).thenReturn("false");

        Property property = new Property();
        property.setName(VoiceOTPConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE);
        property.setValue("true");
        PowerMockito.when(VoiceOTPUtils.getAccountLockConnectorConfigs(authenticatedUser.getTenantDomain()))
                .thenReturn(new Property[]{property});

        PowerMockito.when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        PowerMockito.when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        PowerMockito.when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        PowerMockito.when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);

        SequenceConfig sequenceConfig = new SequenceConfig();
        Map<Integer, StepConfig> stepMap = new HashMap<>();

        StepConfig stepConfig = new StepConfig();
        stepConfig.setSubjectAttributeStep(true);

        AuthenticatedUser authUser = new AuthenticatedUser();
        stepConfig.setAuthenticatedUser(authUser);

        PowerMockito.when(VoiceOTPUtils.isAccountLocked(authenticatedUser)).thenReturn(false);

        stepMap.put(1,stepConfig);
        sequenceConfig.setStepMap(stepMap);

        PowerMockito.when(VoiceOTPUtils.isLocalUser(context)).thenReturn(true);
        PowerMockito.when(VoiceOTPUtils.getBackupCode(context)).thenReturn("true");

        PowerMockito.when(context.getSequenceConfig()).thenReturn(new SequenceConfig());

        Whitebox.invokeMethod(authenticator, "processAuthenticationResponse",
                httpServletRequest, response, context);
    }

    @Test
    public void testCheckWithBackUpCodes() throws Exception {
        
        mockStatic(IdentityTenantUtil.class);
        context.setProperty(VoiceOTPConstants.USER_NAME,"admin");
        PowerMockito.when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        PowerMockito.when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        PowerMockito.when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        PowerMockito.when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier("admin");
        PowerMockito.when((AuthenticatedUser) context.getProperty(VoiceOTPConstants.AUTHENTICATED_USER))
                .thenReturn(authenticatedUser);
        PowerMockito.when(userRealm.getUserStoreManager()
                .getUserClaimValue(MultitenantUtils.getTenantAwareUsername("admin"),
                        VoiceOTPConstants.SAVED_OTP_LIST, null)).thenReturn("12345,4568,1234,7896");
        AuthenticatedUser user = (AuthenticatedUser) context.getProperty(VoiceOTPConstants.AUTHENTICATED_USER);
        mockStatic(FrameworkUtils.class);
        PowerMockito.when(FrameworkUtils.getMultiAttributeSeparator()).thenReturn(",");
        Whitebox.invokeMethod(authenticator, "checkWithBackUpCodes",
                context,"1234",user);
    }

    public void testCheckWithInvalidBackUpCodes() throws Exception {

        mockStatic(IdentityTenantUtil.class);
        mockStatic(VoiceOTPUtils.class);
        context.setProperty(VoiceOTPConstants.USER_NAME,"admin");
        PowerMockito.when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        PowerMockito.when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        PowerMockito.when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        PowerMockito.when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier("admin");
        PowerMockito.when((AuthenticatedUser) context.getProperty(VoiceOTPConstants.AUTHENTICATED_USER))
                .thenReturn(authenticatedUser);
        mockStatic(FrameworkUtils.class);
        PowerMockito.when(FrameworkUtils.getMultiAttributeSeparator()).thenReturn(",");
        PowerMockito.when(userRealm.getUserStoreManager()
                .getUserClaimValue(MultitenantUtils.getTenantAwareUsername("admin"),
                        VoiceOTPConstants.SAVED_OTP_LIST, null)).thenReturn("12345,4568,1234,7896");
        Whitebox.invokeMethod(authenticator, "checkWithBackUpCodes",
                context, "45698789", authenticatedUser);
    }

    @Test
    public void testGetScreenAttribute() throws org.wso2.carbon.user.api.UserStoreException {
        
        mockStatic(IdentityTenantUtil.class);
        mockStatic(VoiceOTPUtils.class);
        PowerMockito.when(VoiceOTPUtils.getScreenUserAttribute(context)).thenReturn
                ("http://wso2.org/claims/mobile");
        PowerMockito.when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        PowerMockito.when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        PowerMockito.when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        PowerMockito.when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        PowerMockito.when(userRealm.getUserStoreManager()
                .getUserClaimValue("admin", "http://wso2.org/claims/mobile", null))
                .thenReturn("0778965231");
        PowerMockito.when(VoiceOTPUtils.getNoOfDigits(context)).thenReturn("4");

        Assert.assertEquals(authenticator
                .getScreenAttribute(context,userRealm,"admin"),"0778******");

        PowerMockito.when(VoiceOTPUtils.getDigitsOrder(context)).thenReturn("backward");
        Assert.assertEquals(authenticator
                .getScreenAttribute(context,userRealm,"admin"),"******5231");
    }

    @Test
    public void testGetScreenAttributeWhenMobileRequest() throws org.wso2.carbon.user.api.UserStoreException {

        mockStatic(IdentityTenantUtil.class);
        mockStatic(VoiceOTPUtils.class);
        PowerMockito.when(VoiceOTPUtils.getScreenUserAttribute(context)).thenReturn
                ("http://wso2.org/claims/mobile");
        PowerMockito.when(context.getProperty(REQUESTED_USER_MOBILE)).thenReturn("0778899889");
        PowerMockito.when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        PowerMockito.when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        PowerMockito.when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        PowerMockito.when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        PowerMockito.when(userRealm.getUserStoreManager()
                .getUserClaimValue("admin", "http://wso2.org/claims/mobile", null)).thenReturn(null);
        PowerMockito.when(VoiceOTPUtils.getNoOfDigits(context)).thenReturn("4");

        Assert.assertEquals(authenticator
                .getScreenAttribute(context, userRealm, "admin"), "0778******");

        PowerMockito.when(VoiceOTPUtils.getDigitsOrder(context)).thenReturn("backward");
        Assert.assertEquals(authenticator
                .getScreenAttribute(context, userRealm, "admin"), "******9889");
    }

    @Test
    public void testUpdateMobileNumberForUsername() throws Exception {
        
        mockStatic(IdentityTenantUtil.class);
        PowerMockito.when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        PowerMockito.when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        PowerMockito.when(realmService.getTenantUserRealm(-1234)).thenReturn(null);
        Whitebox.invokeMethod(authenticator, "updateMobileNumberForUsername",
                context,httpServletRequest,"admin","carbon.super");
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

        Assert.assertEquals(Whitebox.invokeMethod(authenticator, "getOTPSeparationCharacters",
                context),"%2B");
    }

    @Test
    public void testOtpSeparationCharacters() throws Exception {

        PowerMockito.when(context.getAuthenticatorProperties()).thenReturn(authenticatorProperties);
        PowerMockito.when(context.getAuthenticatorProperties().get(OTP_SEPARATOR)).thenReturn("%20");
        Assert.assertEquals(Whitebox.invokeMethod(authenticator, "getOTPSeparationCharacters",
                context),"%20");
    }

    @Test
    public void testDefaultDivisorValue() throws Exception {

        Assert.assertEquals(Integer.toString(Whitebox.invokeMethod(authenticator, "getDivisor",
                context)),"1");
    }

    @Test
    public void testDivisorValue() throws Exception {

        PowerMockito.when(context.getAuthenticatorProperties()).thenReturn(authenticatorProperties);
        PowerMockito.when(context.getAuthenticatorProperties().get(DIVISOR)).thenReturn("2");
        Assert.assertEquals(Integer.toString(Whitebox.invokeMethod(authenticator, "getDivisor",
                context)),"2");

    }

    @Test
    public void testOtpSeparation() throws Exception {

        PowerMockito.when(context.getAuthenticatorProperties()).thenReturn(authenticatorProperties);
        PowerMockito.when(context.getAuthenticatorProperties().get(OTP_SEPARATOR)).thenReturn("%20");
        PowerMockito.when(context.getAuthenticatorProperties().get(DIVISOR)).thenReturn("2");
        Assert.assertEquals(Whitebox.invokeMethod(authenticator, "splitAndFormatOtp",
                "123456",2,context),"12%2034%2056");
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

        Assert.assertEquals(Whitebox
                .invokeMethod(authenticator, "getConnection",
                        httpURLConnection, context, null, null,
                        httpResponse.toString(), receivedMobileNumber, otpToken, "GET"), Boolean.TRUE);
    }

    @Test
    public void testGetConnectionWithUnauthorizedResponse() throws Exception {
        
        String headerString = "Content-Type:application/json";
        String payload = "{\"key\":\"value\"}";
        String httpMethod = "POST";

        URL url = new URL("https://google.lk");

        httpURLConnection = (HttpURLConnection)Mockito.mock(url.openConnection().getClass());
        PowerMockito.when(httpURLConnection.getResponseCode()).thenReturn(401);
        PowerMockito.when(httpURLConnection.getResponseMessage()).thenReturn("Unauthorized");
        PowerMockito.when(httpURLConnection.getOutputStream()).thenReturn(new OutputStream() {
            @Override
            public void write(int b) throws IOException {

            }
        });

        boolean result = Whitebox.invokeMethod(authenticator, "getConnection",
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
        PowerMockito.when(httpURLConnection.getResponseCode()).thenReturn(200);
        PowerMockito.when(httpURLConnection.getResponseMessage()).thenReturn("OK");
        PowerMockito.when(httpURLConnection.getOutputStream()).thenReturn(new ByteArrayOutputStream());

        boolean result = Whitebox.invokeMethod(authenticator, "getConnection",
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

        Map<String, String> authenticatorProperties = new HashMap<>();
        authenticatorProperties.put(VoiceOTPConstants.VOICE_URL, "http://google.lk");
        authenticatorProperties.put(VoiceOTPConstants.HTTP_METHOD, "POST");
        PowerMockito.when(context.getAuthenticatorProperties()).thenReturn(authenticatorProperties);
        PowerMockito.when(VoiceOTPUtils.getLoginPageFromXMLFile(context))
                .thenReturn("authenticationendpoint/voiceOtp.jsp");
        PowerMockito.when(configurationFacade.getAuthenticationEndpointURL())
                .thenReturn("/authenticationendpoint/login.do");
        PowerMockito.when(VoiceOTPUtils.getTokenLength(context)).thenReturn("6");
        PowerMockito.when(VoiceOTPUtils.getTokenExpiryTime(context)).thenReturn("300");
        PowerMockito.when(OneTimePasswordUtils
                .getRandomNumber(VoiceOTPConstants.SECRET_KEY_LENGTH)).thenReturn("123456");

        byte [] test = "12345".getBytes();
        Long testL = Long.parseLong("12345");


        PowerMockito.when(OneTimePasswordUtils.generateToken("123456", "2", 6,
                false)).thenReturn("123456");
        PowerMockito.when(OneTimePasswordUtils
                .generateOTP(test,testL,6,false, 1)).thenReturn("12345");
        PowerMockito.when(authenticator.sendRESTCall(context,"https://testdomain.com/voice", POST_METHOD,
                "Authorization: Basic dGVzdDp0ZXN0",
                "{\"key\":\"key\",\"value\":\"value\"}", "200", "+94123456789",
                "123456")).thenReturn(true);

         
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

    @Test
    public void testSendRestCall() throws AuthenticationFailedException, IOException {

        Map<String, String> authenticatorProperties = new HashMap<>();
        String header = "Authorization: Basic dGVzdDp0ZXN0";
        String httpMethod = "POST";
        String payload = "{\"key\":\"key\",\"value\":\"value\"}";
        String voiceURL = "https://testdomain.com/voice";
        String httpResponse = "200";


        authenticator.sendRESTCall(context,voiceURL,httpMethod,header,payload,
                httpResponse,"+94713933424","123456");
    }

    @Test
    public void testGetMultiOptionURIQueryParam_RequestIsNull() throws Exception {

        HttpServletRequest request = null;

        String result = Whitebox
                .invokeMethod(authenticator, "getMultiOptionURIQueryParam",request);

        Assert.assertEquals(StringUtils.EMPTY, result);
    }

    @Test
    public void testGetMultiOptionURIQueryParam_ParameterIsEmpty() throws Exception {

        HttpServletRequest request = mock(HttpServletRequest.class);
        PowerMockito.when(request.getParameter(VoiceOTPConstants.MULTI_OPTION_URI)).thenReturn("");

        String result = Whitebox.invokeMethod(authenticator,
                "getMultiOptionURIQueryParam",request);

        Assert.assertEquals(StringUtils.EMPTY, result);
    }

    @Test
    public void testGetMultiOptionURIQueryParam_ParameterIsNotEmpty() throws Exception {

        HttpServletRequest request = mock(HttpServletRequest.class);
        String expectedValue = "someValue";
        PowerMockito.when(request.getParameter(VoiceOTPConstants.MULTI_OPTION_URI)).thenReturn(expectedValue);

        String result = Whitebox.invokeMethod(authenticator,
                "getMultiOptionURIQueryParam",request);

        String expectedQueryParam = "&" +
                VoiceOTPConstants.MULTI_OPTION_URI + "=" + Encode.forUriComponent(expectedValue);
        Assert.assertEquals(expectedQueryParam, result);
    }

    @Test
    public void testGetMultiOptionURIQueryParam_ParrameterIsNull() throws Exception {

        HttpServletRequest request = mock(HttpServletRequest.class);
        PowerMockito.when(request.getParameter(VoiceOTPConstants.MULTI_OPTION_URI)).thenReturn(null);

        Assert.assertEquals(Whitebox.invokeMethod(authenticator,
                "getMultiOptionURIQueryParam",request), StringUtils.EMPTY);
    }

    @Test
    public void testHandleVoiceOtpVerificationFailWhenLocalUserWithAccountLockingDisabled() throws Exception {
        
        PowerMockito.when(VoiceOTPUtils.isLocalUser(context)).thenReturn(false);
        invokeHandleVoiceOtpVerificationFailPrivateMethod(authenticator,
                "handleVoiceOtpVerificationFail", context);
        Assert.assertFalse(VoiceOTPUtils.isAccountLockingEnabledForVoiceOtp(context));
    }

    private void invokeHandleVoiceOtpVerificationFailPrivateMethod
            (Object instance, String methodName, Object... args) throws Exception {
        
        Method method = instance.getClass().getDeclaredMethod(methodName,AuthenticationContext.class);
        method.setAccessible(true);
        method.invoke(instance, args);
    }

    @Test
    public void testHandleVoiceOtpVerificationFailWhenAccountAlreadyLocked() throws Exception {
        
        PowerMockito.when(VoiceOTPUtils.isLocalUser(context)).thenReturn(true);
        PowerMockito.when(VoiceOTPUtils.isAccountLockingEnabledForVoiceOtp(context)).thenReturn(true);
        PowerMockito.when((AuthenticatedUser) context.getProperty(VoiceOTPConstants.AUTHENTICATED_USER))
                .thenReturn(authenticatedUser);
        PowerMockito.when(VoiceOTPUtils.isAccountLocked(authenticatedUser)).thenReturn(true);
        invokeHandleVoiceOtpVerificationFailPrivateMethod(authenticator,
                "handleVoiceOtpVerificationFail", context);
        Assert.assertTrue(VoiceOTPUtils.isAccountLockingEnabledForVoiceOtp(context));
    }

    @Test
    public void testHandleVoiceOtpVerificationFailWhenMaxAttemptsExceeded() throws Exception {
        
        PowerMockito.when(VoiceOTPUtils.isLocalUser(context)).thenReturn(true);
        PowerMockito.when(VoiceOTPUtils.isAccountLockingEnabledForVoiceOtp(context)).thenReturn(true);
        PowerMockito.when(VoiceOTPUtils.isAccountLocked(authenticatedUser)).thenReturn(false);
        PowerMockito.when(context.getProperty(VoiceOTPConstants.AUTHENTICATED_USER))
                .thenReturn(authenticatedUser);
        PowerMockito.when(authenticatedUser.getTenantDomain()).thenReturn("testdomain");

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

        Property [] properties  = new Property[]{accountLockOnFailure,accountLockTime,
                loginFailTimeoutRatio,accountLockOnFailureMax};
        PowerMockito.when(VoiceOTPUtils.getAccountLockConnectorConfigs("testdomain"))
                .thenReturn(properties);

        Map<String, String> claims = new HashMap<>();
        claims.put(VoiceOTPConstants.VOICE_OTP_FAILED_ATTEMPTS_CLAIM, "2");
        claims.put(VoiceOTPConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM, "1");
        PowerMockito.when(userStoreManager.getUserClaimValues(anyString(),anyObject(), anyString()))
                .thenReturn(claims);

        invokehandleVoiceOtpVerificationFailPrivateMethod(authenticator,
                "handleVoiceOtpVerificationFail",context);

        verify(VoiceOTPUtils.class, times(1));
        VoiceOTPUtils.getAccountLockConnectorConfigs(anyString());
    }

    private void invokehandleVoiceOtpVerificationFailPrivateMethod
            (Object instance, String methodName, Object... args) throws Exception {
        
        Method method = instance.getClass().getDeclaredMethod(methodName,AuthenticationContext.class);
        method.setAccessible(true);
        method.invoke(instance, args);
    }

    @Test(expectedExceptions=Exception.class)
    public void testHandleVoiceOtpVerificationFailIncrementalFailure() throws Exception {
        
        PowerMockito.when(VoiceOTPUtils.isLocalUser(context)).thenReturn(true);
        PowerMockito.when(VoiceOTPUtils.isAccountLockingEnabledForVoiceOtp(context)).thenReturn(true);
        PowerMockito.when(VoiceOTPUtils.isAccountLocked(authenticatedUser)).thenReturn(false);
        PowerMockito.when(context.getProperty(VoiceOTPConstants.AUTHENTICATED_USER))
                .thenReturn(authenticatedUser);
        PowerMockito.when(authenticatedUser.getTenantDomain()).thenReturn("testdomain");

        Property accountLockOnFailureMax = new Property();
        accountLockOnFailureMax.setName(VoiceOTPConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE_MAX);
        accountLockOnFailureMax.setDefaultValue("3");

        Property [] properties  = new Property[]{accountLockOnFailureMax};
        PowerMockito.when(VoiceOTPUtils.getAccountLockConnectorConfigs("testdomain"))
                .thenReturn(properties);

        Map<String, String> claims = new HashMap<>();
        claims.put(VoiceOTPConstants.VOICE_OTP_FAILED_ATTEMPTS_CLAIM, "1");
        PowerMockito.when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        PowerMockito.when(userStoreManager.getUserClaimValues(anyString(),anyObject(), anyString()))
                .thenReturn(claims);

        PowerMockito.when(IdentityTenantUtil.getTenantId("testdomain")).thenReturn(1);
        PowerMockito.when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        PowerMockito.when(realmService.getTenantUserRealm(1)).thenReturn(userRealm);

        invokehandleVoiceOtpVerificationFailPrivateMethod
                (authenticator,"handleVoiceOtpVerificationFail",context);
    }

    @Test
    public void testResetVoiceOtpFailedAttemptsWhenAccountLockingEnabledOrFederatedFlow() throws Exception {
        
        PowerMockito.when(VoiceOTPUtils.isLocalUser(context)).thenReturn(true);
        PowerMockito.when(VoiceOTPUtils.isAccountLockingEnabledForVoiceOtp(context)).thenReturn(true);
        PowerMockito.when(context.getProperty(VoiceOTPConstants.AUTHENTICATED_USER))
                .thenReturn(authenticatedUser);
        PowerMockito.when(authenticatedUser.getTenantDomain()).thenReturn("testdomain");

        Property accountLockOnFailure = new Property();
        accountLockOnFailure.setName(VoiceOTPConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE);
        accountLockOnFailure.setDefaultValue("false");


        Property [] properties  = new Property[]{};
        PowerMockito.when(VoiceOTPUtils.getAccountLockConnectorConfigs("testdomain"))
                .thenReturn(properties);

        PowerMockito.when(IdentityUtil.addDomainToName(authenticatedUser.getUserName(),
                authenticatedUser.getUserStoreDomain())).thenReturn("testuser@tenantdomain");
        PowerMockito.when(IdentityTenantUtil.getTenantId("testdomain")).thenReturn(1);
        PowerMockito.when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        PowerMockito.when(realmService.getTenantUserRealm(1)).thenReturn(userRealm);

        Map<String, String> claims = new HashMap<>();
        claims.put(VoiceOTPConstants.VOICE_OTP_FAILED_ATTEMPTS_CLAIM, "1");
        PowerMockito.when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        PowerMockito.when(userStoreManager.getUserClaimValues(anyString(),anyObject(), anyString()))
                .thenReturn(claims);

        invokeResetVoiceOtpFailedAttemptsPrivateMethod
                (authenticator,"resetVoiceOtpFailedAttempts",context);
    }

    private void invokeResetVoiceOtpFailedAttemptsPrivateMethod
            (Object instance, String methodName, Object... args) throws Exception {
        
        Method method = instance.getClass().getDeclaredMethod(methodName,AuthenticationContext.class);
        method.setAccessible(true);
        method.invoke(instance, args);
    }
    @Test(expectedExceptions = Exception.class)
    public void testGetUnlockTimeInMilliSecondsWhenUserRealmIsNull() throws Exception {
        
        String username = "testuser";
        PowerMockito.when(authenticatedUser.toFullQualifiedUsername()).thenReturn(username);
        PowerMockito.when(MultitenantUtils.getTenantAwareUsername(username))
                .thenReturn("testuser@testdomain");
        PowerMockito.when(IdentityTenantUtil.getTenantId("testdomain")).thenReturn(1);
        PowerMockito.when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        PowerMockito.when(realmService.getTenantUserRealm(1)).thenReturn(null);
        PowerMockito.when(userRealm.getUserStoreManager()).thenReturn(null);
        invokegetUnlockTimeInMilliSecondsPrivateMethod
                (authenticator,"getUnlockTimeInMilliSeconds",authenticatedUser);
    }


    private void invokegetUnlockTimeInMilliSecondsPrivateMethod
            (Object instance, String methodName, Object... args) throws Exception {
        
        Method method = instance.getClass().getDeclaredMethod(methodName,AuthenticatedUser.class);
        method.setAccessible(true);
        method.invoke(instance, args);
    }

    @Test
    public void testGetUnlockTimeInMilliSecondsWhenClaimValueConfigured() throws Exception {
        
        String username = "testuser";
        String tenantAwareUsername = "testuser@testdomain";
        realmService = mock(RealmService.class);
        userRealm = mock(UserRealm.class);
        PowerMockito.when(authenticatedUser.toFullQualifiedUsername()).thenReturn(username);
        PowerMockito.when(MultitenantUtils.getTenantAwareUsername(username)).thenReturn(tenantAwareUsername);
        PowerMockito.when(MultitenantUtils.getTenantDomain(username)).thenReturn("testdomain");
        PowerMockito.when(IdentityTenantUtil.getTenantId("testdomain")).thenReturn(1);
        PowerMockito.when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        PowerMockito.when(realmService.getTenantUserRealm(1)).thenReturn(userRealm);
        PowerMockito.when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);

        Map<String, String> claimValues = new HashMap<>();
        claimValues.put(VoiceOTPConstants.ACCOUNT_UNLOCK_TIME_CLAIM, "123456789");
        PowerMockito.when(userStoreManager.getUserClaimValues(tenantAwareUsername,
                new String[]{VoiceOTPConstants.ACCOUNT_UNLOCK_TIME_CLAIM},
                null)).thenReturn(claimValues);

        long unlockTime = (long) invokegetUnlockTimeInMilliSecondsPrivateMethodWithReturn
                (authenticator,"getUnlockTimeInMilliSeconds",authenticatedUser);
        Assert.assertEquals(123456789L, unlockTime);
    }

    private Object invokegetUnlockTimeInMilliSecondsPrivateMethodWithReturn
            (Object instance, String methodName, Object... args) throws Exception {
        
        Method method = instance.getClass().getDeclaredMethod(methodName,AuthenticatedUser.class);
        method.setAccessible(true);
        return method.invoke(instance, args);
    }

    @Test(expectedExceptions = Exception.class)
    public void testProcessValidUserTokenFail() throws Exception {

        PowerMockito.when(context.getProperty(VoiceOTPConstants.TOKEN_VALIDITY_TIME)).thenReturn(6);
        PowerMockito.when(context.getProperty(VoiceOTPConstants.SENT_OTP_TOKEN_TIME)).thenReturn(otpTime);

        invokeProcessValidUserTokenPrivateMethod
                (authenticator,"processValidUserToken",context,authenticatedUser);
    }

    @Test
    public void testProcessValidUserTokenSuccess() throws Exception {

        PowerMockito.when(context.getProperty(VoiceOTPConstants.TOKEN_VALIDITY_TIME))
                .thenReturn(System.currentTimeMillis());
        PowerMockito.when(context.getProperty(VoiceOTPConstants.SENT_OTP_TOKEN_TIME)).thenReturn(otpTime);

        invokeProcessValidUserTokenPrivateMethod
                (authenticator,"processValidUserToken",context,authenticatedUser);
    }

    private void invokeProcessValidUserTokenPrivateMethod
            (Object instance, String methodName, Object... args) throws Exception {
        
        Method method = instance.getClass().getDeclaredMethod
                (methodName,AuthenticationContext.class,AuthenticatedUser.class);
        method.setAccessible(true);
        method.invoke(instance, args);
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new PowerMockObjectFactory();
    }
}
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

import org.mockito.Mock;
import org.mockito.Spy;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.extension.identity.helper.IdentityHelperConstants;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.authenticator.voiceotp.VoiceOTPConstants;
import org.wso2.carbon.identity.authenticator.voiceotp.VoiceOTPUtils;
import org.wso2.carbon.identity.authenticator.voiceotp.exception.VoiceOTPException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.mockStatic;

@PrepareForTest({FileBasedConfigurationBuilder.class, IdentityTenantUtil.class})
@PowerMockIgnore({"org.mockito.*"})
public class VoiceOTPUtilsTest {

    @Mock
    private UserStoreManager userStoreManager;

    @Mock
    private UserRealm userRealm;

    @Mock
    private RealmService realmService;

    @Mock
    private FileBasedConfigurationBuilder fileBasedConfigurationBuilder;

    @Spy
    private AuthenticationContext context;


    @BeforeMethod
    public void setUp() throws Exception {
        mockStatic(FileBasedConfigurationBuilder.class);
        initMocks(this);
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new PowerMockObjectFactory();
    }

    @AfterMethod
    public void tearDown() throws Exception {
    }

    @Test
    public void testGetConfigurationFromRegistry() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(VoiceOTPConstants.IS_VOICEOTP_MANDATORY, true);
        authenticationContext.setProperty("getPropertiesFromLocal", null);
        Assert.assertEquals(VoiceOTPUtils.getConfiguration(authenticationContext,
                VoiceOTPConstants.IS_VOICEOTP_MANDATORY), "true");
    }

    @Test
    public void testGetConfigurationFromLocalFile() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("carbon.super");
        authenticationContext.setProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY,
                IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        Map<String, String> parameters = new HashMap<String, String>();
        parameters.put(VoiceOTPConstants.IS_VOICEOTP_MANDATORY, "true");
        parameters.put(VoiceOTPConstants.IS_ENABLED_RESEND, "true");
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        authenticatorConfig.setParameterMap(parameters);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        Assert.assertEquals(VoiceOTPUtils.getConfiguration(authenticationContext,
                VoiceOTPConstants.IS_VOICEOTP_MANDATORY), "true");
    }

    @Test
    public void testGetBackupCodeFromRegistry() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(VoiceOTPConstants.BACKUP_CODE, true);
        Assert.assertEquals(VoiceOTPUtils.getBackupCode(authenticationContext), "true");
    }

    @Test
    public void testGetDigitsOrderFromRegistry() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(VoiceOTPConstants.ORDER, "backward");
        Assert.assertEquals(VoiceOTPUtils.getDigitsOrder(authenticationContext), "backward");
    }

    @Test
    public void testGetNoOfDigitsFromRegistry() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(VoiceOTPConstants.NO_DIGITS, "4");
        Assert.assertEquals(VoiceOTPUtils.getNoOfDigits(authenticationContext), "4");
    }

    @Test
    public void testGetScreenUserAttributeFromRegistry() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(VoiceOTPConstants.SCREEN_USER_ATTRIBUTE, "http://wso2.org/claims/mobile");
        Assert.assertEquals(VoiceOTPUtils.getScreenUserAttribute(authenticationContext),
                "http://wso2.org/claims/mobile");
    }

    @Test
    public void testGetMobileNumberRequestPageFromRegistry() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(VoiceOTPConstants.MOBILE_NUMBER_REQ_PAGE,
                "authenticationendpoint/mobile.jsp");
        Assert.assertEquals(VoiceOTPUtils.getMobileNumberRequestPage(authenticationContext),
                "authenticationendpoint/mobile.jsp");
    }

    @Test
    public void testIsRetryEnabledFromRegistry() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(VoiceOTPConstants.IS_ENABLED_RETRY, "true");
        Assert.assertEquals(VoiceOTPUtils.isRetryEnabled(authenticationContext), true);
    }

    @Test
    public void testGetErrorPageFromXMLFileFromRegistry() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(VoiceOTPConstants.VOICEOTP_AUTHENTICATION_ERROR_PAGE_URL,
                VoiceOTPConstants.ERROR_PAGE);
        Assert.assertEquals(VoiceOTPUtils.getErrorPageFromXMLFile(authenticationContext),
                "authenticationendpoint/voiceOtpError.jsp");
    }

    @Test
    public void testGetLoginPageFromXMLFileFromRegistry() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(VoiceOTPConstants.VOICEOTP_AUTHENTICATION_ENDPOINT_URL,
                VoiceOTPConstants.VOICE_LOGIN_PAGE);
        Assert.assertEquals(VoiceOTPUtils.getLoginPageFromXMLFile(authenticationContext),
                "authenticationendpoint/voiceOtp.jsp");
    }

    @Test
    public void testIsEnableResendCodeFromRegistry() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(VoiceOTPConstants.IS_ENABLED_RESEND, "true");
        Assert.assertEquals(VoiceOTPUtils.isEnableResendCode(authenticationContext), true);
    }

    @Test
    public void testIsEnableMobileNoUpdateFromRegistry() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(VoiceOTPConstants.IS_ENABLE_MOBILE_NO_UPDATE, "true");
        Assert.assertEquals(VoiceOTPUtils.isEnableMobileNoUpdate(authenticationContext), true);
    }

    @Test
    public void testIsVoiceOTPEnableByUserFromRegistry() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(VoiceOTPConstants.IS_VOICEOTP_ENABLE_BY_USER, "true");
        Assert.assertEquals(VoiceOTPUtils.isVoiceOTPEnabledByUser(authenticationContext), true);
    }

    @Test
    public void testIsSendOTPDirectlyToMobileFromRegistry() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(VoiceOTPConstants.IS_SEND_OTP_DIRECTLY_TO_MOBILE, "true");
        Assert.assertEquals(VoiceOTPUtils.isSendOTPDirectlyToMobile(authenticationContext), true);
    }

    @Test
    public void testIsVoiceOTPMandatoryFromRegistry() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(VoiceOTPConstants.IS_VOICEOTP_MANDATORY, "true");
        Assert.assertEquals(VoiceOTPUtils.isVoiceOTPMandatory(authenticationContext), true);
    }

    @Test
    public void testIsVoiceOTPMandatoryFromLocalFile() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY,
                IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        authenticationContext.setProperty(VoiceOTPConstants.IS_VOICEOTP_MANDATORY, "true");
        authenticationContext.setTenantDomain("carbon.super");
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        Map<String, String> parameters = new HashMap<String, String>();
        parameters.put(VoiceOTPConstants.IS_VOICEOTP_MANDATORY, "true");
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        authenticatorConfig.setParameterMap(parameters);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        Assert.assertEquals(VoiceOTPUtils.isVoiceOTPMandatory(authenticationContext), true);
    }

    @Test
    public void testIsEnableAlphanumericTokenFromRegistry() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(VoiceOTPConstants.IS_ENABLE_ALPHANUMERIC_TOKEN, "true");
        Assert.assertEquals(VoiceOTPUtils.isEnableAlphanumericToken(authenticationContext), true);
    }

    @Test
    public void testTokenExpiryTimeFromRegistry() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(VoiceOTPConstants.TOKEN_EXPIRY_TIME, "30");
        Assert.assertEquals(VoiceOTPUtils.getTokenExpiryTime(authenticationContext), "30");
    }

    @Test
    public void testTokenLengthFromRegistry() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(VoiceOTPConstants.TOKEN_LENGTH, "8");
        Assert.assertEquals(VoiceOTPUtils.getTokenLength(authenticationContext), "8");
    }

    @Test
    public void testGetVoiceParameters() {
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        Map<String, String> parameters = new HashMap<String, String>();
        parameters.put(VoiceOTPConstants.IS_VOICEOTP_MANDATORY, "true");
        parameters.put(VoiceOTPConstants.IS_SEND_OTP_DIRECTLY_TO_MOBILE, "false");
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);

        //test with empty parameters map.
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(null);
        Assert.assertEquals(VoiceOTPUtils.getVoiceParameters(), Collections.emptyMap());

        //test with non-empty parameters map.
        authenticatorConfig.setParameterMap(parameters);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        Assert.assertEquals(VoiceOTPUtils.getVoiceParameters(), parameters);
    }

    @Test
    public void testIsVoiceOTPDisableForLocalUser() throws UserStoreException, AuthenticationFailedException,
            VoiceOTPException {
        mockStatic(IdentityTenantUtil.class);
        String username = "admin";
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(VoiceOTPUtils.isVoiceOTPEnabledByUser(context)).thenReturn(true);
        Map<String, String> claims = new HashMap<>();
        claims.put(VoiceOTPConstants.USER_VOICEOTP_DISABLED_CLAIM_URI, "false");
        userStoreManager.setUserClaimValues(MultitenantUtils.getTenantAwareUsername(username), claims, null);
        Assert.assertEquals(VoiceOTPUtils.isVoiceOTPDisableForLocalUser(anyString(), context), false);
    }

    @Test(expectedExceptions = {VoiceOTPException.class})
    public void testVerifyUserExists() throws UserStoreException, AuthenticationFailedException, VoiceOTPException {
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(VoiceOTPUtils.getUserRealm("carbon.super")).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        VoiceOTPUtils.verifyUserExists("admin", "carbon.super");
    }

    @Test
    public void testGetMobileNumberForUsername() throws UserStoreException, VoiceOTPException,
            AuthenticationFailedException {
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        Assert.assertEquals(VoiceOTPUtils.getMobileNumberForUsername("admin"), null);
    }

    @Test(expectedExceptions = {VoiceOTPException.class})
    public void testGetMobileNumberForUsernameWithException() throws UserStoreException, VoiceOTPException,
            AuthenticationFailedException {
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(null);
        VoiceOTPUtils.getMobileNumberForUsername("admin");
    }

    @Test(expectedExceptions = {VoiceOTPException.class})
    public void testUpdateUserAttributeWithException() throws UserStoreException, VoiceOTPException {
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(null);
        Map<String, String> claims = new HashMap<>();
        VoiceOTPUtils.updateUserAttribute(anyString(), claims, "carbon.super");
    }

    @Test
    public void testUpdateUserAttribute() throws UserStoreException, VoiceOTPException {
        mockStatic(IdentityTenantUtil.class);
        Map<String, String> claims = new HashMap<>();
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.isExistingUser(anyString())).thenReturn(true);
        VoiceOTPUtils.updateUserAttribute("admin", claims, "carbon.super");
    }
}
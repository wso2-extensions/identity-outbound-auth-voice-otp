/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.authenticator.voiceotp;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.extension.identity.helper.IdentityHelperConstants;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.authenticator.voiceotp.exception.VoiceOTPException;
import org.wso2.carbon.identity.authenticator.voiceotp.internal.VoiceOTPServiceDataHolder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.Collections;
import java.util.Map;

public class VoiceOTPUtils {

    private static final Log log = LogFactory.getLog(VoiceOTPUtils.class);
    private static boolean useInternalErrorCodes = true;

    /**
     * Get parameter values from application-authentication.xml local file.
     */
    public static Map<String, String> getVoiceParameters() {

        AuthenticatorConfig authConfig = FileBasedConfigurationBuilder.getInstance()
                .getAuthenticatorBean(VoiceOTPConstants.AUTHENTICATOR_NAME);
        if (authConfig != null) {
            return authConfig.getParameterMap();
        }
        if (log.isDebugEnabled()) {
            log.debug("Authenticator configs not found. Hence returning an empty map");
        }
        return Collections.emptyMap();
    }

    /**
     * Check whether VoiceOTP is disable by user.
     *
     * @param username the Username
     * @param context  the AuthenticationContext
     * @return true or false
     * @throws VoiceOTPException
     */
    public static boolean isVoiceOTPDisableForLocalUser(String username, AuthenticationContext context)
            throws VoiceOTPException {

        UserRealm userRealm;
        try {
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = IdentityTenantUtil.getRealmService();
            userRealm = realmService.getTenantUserRealm(tenantId);
            username = MultitenantUtils.getTenantAwareUsername(String.valueOf(username));
            boolean isEnablingControlledByUser = isVoiceOTPEnableOrDisableByUser(context);
            if (userRealm != null) {
                if (isEnablingControlledByUser) {
                    Map<String, String> claimValues = userRealm.getUserStoreManager().getUserClaimValues(username,
                            new String[]{VoiceOTPConstants.USER_VOICEOTP_DISABLED_CLAIM_URI}, null);
                    return Boolean.parseBoolean(claimValues.get(VoiceOTPConstants.USER_VOICEOTP_DISABLED_CLAIM_URI));
                }
            } else {
                throw new VoiceOTPException("Cannot find the user realm for the given tenant domain : " + CarbonContext
                        .getThreadLocalCarbonContext().getTenantDomain());
            }
        } catch (UserStoreException e) {
            throw new VoiceOTPException("Failed while trying to access userRealm of the user : " + username, e);
        }
        return false;
    }

    /**
     * Update the mobile number (user attribute) in user's profile.
     *
     * @param username  the Username
     * @param attribute the Attribute
     * @throws VoiceOTPException
     * @throws UserStoreException
     */
    public static void updateUserAttribute(String username, Map<String, String> attribute, String tenantDomain)
            throws VoiceOTPException, UserStoreException {

        try {
            // updating user attributes is independent from tenant association.not tenant association check needed here.
            UserRealm userRealm;
            // user is always in the super tenant.
            userRealm = VoiceOTPUtils.getUserRealm(tenantDomain);
            if (userRealm == null) {
                throw new VoiceOTPException("The specified tenant domain " + tenantDomain + " does not exist.");
            }
            // check whether user already exists in the system.
            VoiceOTPUtils.verifyUserExists(username, tenantDomain);
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            userStoreManager.setUserClaimValues(username, attribute, null);
        } catch (AuthenticationFailedException e) {
            throw new VoiceOTPException("Exception occurred while connecting to User Store: Authentication is failed. ", e);
        }
    }

    /**
     * Verify whether user Exist in the user store or not.
     *
     * @param username the Username
     * @throws VoiceOTPException
     */
    public static void verifyUserExists(String username, String tenantDomain) throws VoiceOTPException,
            AuthenticationFailedException {

        UserRealm userRealm;
        boolean isUserExist = false;
        try {
            userRealm = VoiceOTPUtils.getUserRealm(tenantDomain);
            if (userRealm == null) {
                throw new VoiceOTPException("Super tenant realm not loaded.");
            }
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            if (userStoreManager.isExistingUser(username)) {
                isUserExist = true;
            }
        } catch (UserStoreException e) {
            throw new VoiceOTPException("Error while validating the user.", e);
        }
        if (!isUserExist) {
            if (log.isDebugEnabled()) {
                log.debug("User does not exist in the User Store");
            }
            throw new VoiceOTPException("User does not exist in the User Store.");
        }
    }

    /**
     * Get the user realm of the logged in user.
     *
     * @param tenantDomain the tenantDomain
     * @return th user realm
     * @throws AuthenticationFailedException
     */
    public static UserRealm getUserRealm(String tenantDomain) throws AuthenticationFailedException {

        UserRealm userRealm;
        try {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = IdentityTenantUtil.getRealmService();
            userRealm = realmService.getTenantUserRealm(tenantId);
        } catch (Exception e) {
            throw new AuthenticationFailedException("Cannot find the user realm for the tenant domain "
                    + tenantDomain, e);
        }
        return userRealm;
    }

    /**
     * Get the mobile number for Username.
     *
     * @param username the username
     * @return mobile number
     * @throws VoiceOTPException
     */
    public static String getMobileNumberForUsername(String username) throws VoiceOTPException,
            AuthenticationFailedException {

        UserRealm userRealm;
        String mobile;
        try {
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
            userRealm = getUserRealm(tenantDomain);
            if (userRealm != null) {
                mobile = userRealm.getUserStoreManager()
                        .getUserClaimValue(tenantAwareUsername, VoiceOTPConstants.MOBILE_CLAIM, null);
            } else {
                throw new VoiceOTPException("Cannot find the user realm for the given tenant domain : " + tenantDomain);
            }
        } catch (UserStoreException e) {
            throw new VoiceOTPException("Cannot find the user " + username + " to get the mobile number ", e);
        }
        return mobile;
    }

    /**
     * Check whether VoiceOTP is mandatory or not.
     *
     * @param context the AuthenticationContext
     * @return true or false
     */
    public static boolean isVoiceOTPMandatory(AuthenticationContext context) {

        return Boolean.parseBoolean(getConfiguration(context, VoiceOTPConstants.IS_VOICEOTP_MANDATORY));
    }

    /**
     * Check whether admin enable to send otp directly to mobile number or not.
     *
     * @param context the AuthenticationContext
     * @return true or false
     */
    public static boolean isSendOTPDirectlyToMobile(AuthenticationContext context) {

        return Boolean.parseBoolean(getConfiguration(context, VoiceOTPConstants.IS_SEND_OTP_DIRECTLY_TO_MOBILE));
    }

    /**
     * Check whether admin enable to send otp directly to mobile number which gets from federated idp claims.
     *
     * @param context the AuthenticationContext
     * @return true or false
     */
    public static boolean sendOtpToFederatedMobile(AuthenticationContext context) {

        return Boolean.parseBoolean(getConfiguration(context, VoiceOTPConstants.IS_SEND_OTP_TO_FEDERATED_MOBILE));
    }

    /**
     * Check whether user enable the second factor or not.
     *
     * @param context the AuthenticationContext
     * @return true or false
     */
    public static boolean isVoiceOTPEnableOrDisableByUser(AuthenticationContext context) {

        return Boolean.parseBoolean(getConfiguration(context, VoiceOTPConstants.IS_VOICEOTP_ENABLE_BY_USER));
    }

    /**
     * Check whether admin enable to enter and update a mobile number in user profile when user forgets to register
     * the mobile number or not.
     *
     * @param context the AuthenticationContext
     * @return true or false
     */
    public static boolean isEnableMobileNoUpdate(AuthenticationContext context) {

        return Boolean.parseBoolean(getConfiguration(context, VoiceOTPConstants.IS_ENABLE_MOBILE_NO_UPDATE));
    }

    /**
     * Check whether resend functionality enable or not.
     *
     * @param context the AuthenticationContext
     * @return true or false
     */
    public static boolean isEnableResendCode(AuthenticationContext context) {

        return Boolean.parseBoolean(getConfiguration(context, VoiceOTPConstants.IS_ENABLED_RESEND));
    }

    /**
     * Get the error page url from the application-authentication.xml file.
     *
     * @param context the AuthenticationContext
     * @return errorPage
     */
    public static String getErrorPageFromXMLFile(AuthenticationContext context) {

        return getConfiguration(context, VoiceOTPConstants.VOICEOTP_AUTHENTICATION_ERROR_PAGE_URL);
    }

    /**
     * Get the login page url from the application-authentication.xml file.
     *
     * @param context the AuthenticationContext
     * @return loginPage
     */
    public static String getLoginPageFromXMLFile(AuthenticationContext context) {

        return getConfiguration(context, VoiceOTPConstants.VOICEOTP_AUTHENTICATION_ENDPOINT_URL);
    }

    /**
     * Check whether retry functionality enable or not.
     *
     * @param context the AuthenticationContext
     * @return true or false
     */
    public static boolean isRetryEnabled(AuthenticationContext context) {

        return Boolean.parseBoolean(getConfiguration(context, VoiceOTPConstants.IS_ENABLED_RETRY));
    }

    /**
     * Get the mobile number request page url from the application-authentication.xml file.
     *
     * @param context the AuthenticationContext
     * @return mobile number request page
     */
    public static String getMobileNumberRequestPage(AuthenticationContext context) {

        return getConfiguration(context, VoiceOTPConstants.MOBILE_NUMBER_REQ_PAGE);
    }

    /**
     * Get the screen user attribute.
     *
     * @param context the AuthenticationContext
     * @return screenUserAttribute
     */
    public static String getScreenUserAttribute(AuthenticationContext context) {

        return getConfiguration(context, VoiceOTPConstants.SCREEN_USER_ATTRIBUTE);
    }

    /**
     * Check the number of digits of claim value to show in UI.
     *
     * @param context the AuthenticationContext
     * @return noOfDigits
     */
    public static String getNoOfDigits(AuthenticationContext context) {

        return getConfiguration(context, VoiceOTPConstants.NO_DIGITS);
    }

    /**
     * Check the order whether first number or last of n digits.
     *
     * @param context the AuthenticationContext
     * @return digitsOrder
     */
    public static String getDigitsOrder(AuthenticationContext context) {

        return getConfiguration(context, VoiceOTPConstants.ORDER);
    }

    /**
     * Check whether admin allows to use the backup codes or not
     *
     * @param context the AuthenticationContext
     * @return backupCode
     */
    public static String getBackupCode(AuthenticationContext context) {

        return getConfiguration(context, VoiceOTPConstants.BACKUP_CODE);

    }

    /**
     * Check whether using internal error codes is supported.
     *
     * @param context Authentication Context.
     * @return True if UseInternalError codes is enabled, else return false.
     */
    public static boolean useInternalErrorCodes(AuthenticationContext context) {

        String useVoiceProviderCodesConfig = getConfiguration(context, VoiceOTPConstants.USE_INTERNAL_ERROR_CODES);
        if (StringUtils.isNotEmpty(useVoiceProviderCodesConfig)) {
            useInternalErrorCodes = Boolean.parseBoolean(useVoiceProviderCodesConfig);
            if (log.isDebugEnabled()) {
                log.debug("UseInternalErrorCodes config is enabled in Voice-OTP Authenticator configuration");
            }
        }
        return useInternalErrorCodes;
    }

    /**
     * Return the value for UseInternalErrorCodes.
     *
     * @return useInternalErrorCodes.
     */
    public static boolean useInternalErrorCodes() {

        return useInternalErrorCodes;
    }
    /**
     * Check whether admin allows to generate the alphanumeric token or not.
     *
     * @param context the AuthenticationContext
     * @return true or false
     */
    public static boolean isEnableAlphanumericToken(AuthenticationContext context) {

        return Boolean.parseBoolean(getConfiguration(context, VoiceOTPConstants.IS_ENABLE_ALPHANUMERIC_TOKEN));
    }

    /**
     * Get the token expiry time.
     *
     * @param context the AuthenticationContext
     * @return tokenExpiryTime
     */
    public static String getTokenExpiryTime(AuthenticationContext context) {

        return getConfiguration(context, VoiceOTPConstants.TOKEN_EXPIRY_TIME);
    }

    /**
     * Get the token length.
     *
     * @param context the AuthenticationContext
     * @return tokenLength
     */
    public static String getTokenLength(AuthenticationContext context) {

        return getConfiguration(context, VoiceOTPConstants.TOKEN_LENGTH);
    }

    /**
     * Read configurations from application-authentication.xml for given authenticator.
     *
     * @param context    Authentication Context.
     * @param configName Name of the config.
     * @return Config value.
     */
    public static String getConfiguration(AuthenticationContext context, String configName) {

        String configValue = null;
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        String tenantDomain = context.getTenantDomain();
        if ((propertiesFromLocal != null || MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) &&
                getVoiceParameters().containsKey(configName)) {
            configValue = getVoiceParameters().get(configName);
        } else if ((context.getProperty(configName)) != null) {
            configValue = String.valueOf(context.getProperty(configName));
        }
        if (log.isDebugEnabled()) {
            log.debug("Config value for key " + configName + " for tenant " + tenantDomain + " : " +
                    configValue);
        }
        return configValue;
    }

    /**
     * Check whether ShowAuthFailureReason is enabled or not.
     *
     * @param context Authentication context.
     * @return True if showing authentication failure reason is enabled.
     */
    public static boolean isShowAuthFailureReason(AuthenticationContext context) {

        return Boolean.parseBoolean(getConfiguration(context, VoiceOTPConstants.SHOW_AUTH_FAILURE_REASON));
    }

    /**
     * Check whether account locking is enabled for Voice OTP.
     *
     * @param context Authentication context.
     * @return Whether account locking is enabled for Voice OTP.
     */
    public static boolean isAccountLockingEnabledForVoiceOtp(AuthenticationContext context) {

        return Boolean
                .parseBoolean(getConfiguration(context, VoiceOTPConstants.ENABLE_ACCOUNT_LOCKING_FOR_FAILED_ATTEMPTS));
    }

    /**
     * Check whether the given user account is locked.
     *
     * @param authenticatedUser Authenticated user.
     * @return True if user account is locked.
     * @throws AuthenticationFailedException Exception on authentication failure.
     */
    public static boolean isAccountLocked(AuthenticatedUser authenticatedUser) throws AuthenticationFailedException {

        try {
            return VoiceOTPServiceDataHolder.getInstance().getAccountLockService()
                    .isAccountLocked(authenticatedUser.getUserName(), authenticatedUser.getTenantDomain(),
                            authenticatedUser.getUserStoreDomain());
        } catch (Exception e) {
            String errorMessage = String.format("Error while validating account lock status of user: %s.",
                    authenticatedUser.getUserName());
            throw new AuthenticationFailedException(errorMessage, e);
        }
    }

    /**
     * Get Account Lock Connector Configs.
     *
     * @param tenantDomain Tenant domain.
     * @return Account Lock Connector configs.
     * @throws AuthenticationFailedException Exception on authentication failure.
     */
    public static Property[] getAccountLockConnectorConfigs(String tenantDomain) throws AuthenticationFailedException {

        Property[] connectorConfigs;
        try {
            connectorConfigs = VoiceOTPServiceDataHolder.getInstance()
                    .getIdentityGovernanceService()
                    .getConfiguration(
                            new String[]{
                                    VoiceOTPConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE,
                                    VoiceOTPConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE_MAX,
                                    VoiceOTPConstants.PROPERTY_ACCOUNT_LOCK_TIME,
                                    VoiceOTPConstants.PROPERTY_LOGIN_FAIL_TIMEOUT_RATIO
                            }, tenantDomain);
        } catch (Exception e) {
            throw new AuthenticationFailedException("Error occurred while retrieving account lock connector " +
                    "configuration", e);
        }

        return connectorConfigs;
    }

    /**
     * Check whether the user being authenticated via a local authenticator or not.
     *
     * @param context Authentication context.
     * @return Whether the user being authenticated via a local authenticator.
     */
    public static boolean isLocalUser(AuthenticationContext context) {

        Map<Integer, StepConfig> stepConfigMap = context.getSequenceConfig().getStepMap();
        if(stepConfigMap != null) {
            for (StepConfig stepConfig : stepConfigMap.values()) {
                if (stepConfig.getAuthenticatedUser() != null && stepConfig.isSubjectAttributeStep()) {
                    if (stepConfig.getAuthenticatedIdP().equals(VoiceOTPConstants.LOCAL_AUTHENTICATOR)) {
                        return true;
                    }
                    break;
                }
            }
        }
        return false;
    }

    /**
     * Checks whether the payload encoding for voice otp is enabled.
     *
     * @param context Authentication context.
     * @return True if encoding is enabled.
     */
    public static boolean isPayloadEncodingForVoiceOTPEnabled(AuthenticationContext context) {

        return Boolean
                .parseBoolean(getConfiguration(context, VoiceOTPConstants.ENABLE_PAYLOAD_ENCODING_FOR_VOICE_OTP));
    }

    /**
     * Checks whether the otp number split is enabled
     *
     * @param context Authentication context.
     * @return True if splitting is enabled.
     */
    public static boolean isOTPNumberSplitEnabled(AuthenticationContext context) {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();

        String isSplitEnabled = authenticatorProperties.get(VoiceOTPConstants.OTP_NUMBER_SPLIT_ENABLED);

        if(isSplitEnabled != null && !isSplitEnabled.isEmpty()){
            return Boolean.parseBoolean(isSplitEnabled);
        }
        return true;
    }

    /**
     * Split the given number by provided divisor
     *
     * @param context Authentication context.
     * @return split number
     */

    public static String splitAndEncodeNumber(String otp, int divisor, AuthenticationContext context) {
        StringBuilder result = new StringBuilder();
        String otpSeparationCharacters = VoiceOTPUtils.getOTPSeparationCharacters(context);
        for (int i = 0; i < otp.length(); i += divisor) {
            int endIndex = Math.min(i + divisor, otp.length());
            result.append(otp.substring(i, endIndex)).append(otpSeparationCharacters);
        }
        return result.substring(0,result.length()-otpSeparationCharacters.length());
    }

    public static String getOTPSeparationCharacters(AuthenticationContext context){

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        String otpSeparationCharacters =  authenticatorProperties.get(VoiceOTPConstants.OTP_SEPARATOR);
        if(otpSeparationCharacters != null){
            return otpSeparationCharacters;
        }else{
            return VoiceOTPConstants.DEFAULT_OTP_SEPARATOR;
        }

    }

    /**
     * Get the regex masking the screen value.
     *
     * @param context Authentication context.
     * @return regex for masking screen value.
     */
    public static String getScreenValueRegex(AuthenticationContext context) {

        return getConfiguration(context, VoiceOTPConstants.SCREEN_VALUE_REGEX);
    }
}

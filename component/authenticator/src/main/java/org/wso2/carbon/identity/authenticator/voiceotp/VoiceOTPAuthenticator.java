/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.authenticator.voiceotp;

import com.google.gson.Gson;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.owasp.encoder.Encode;
import org.slf4j.MDC;
import org.wso2.carbon.extension.identity.helper.FederatedAuthenticatorUtil;
import org.wso2.carbon.extension.identity.helper.IdentityHelperConstants;
import org.wso2.carbon.extension.identity.helper.util.IdentityHelperUtil;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.authenticator.voiceotp.exception.VoiceOTPException;
import org.wso2.carbon.identity.authenticator.voiceotp.internal.VoiceOTPServiceDataHolder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.governance.service.notification.NotificationChannels;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreClientException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import javax.net.ssl.HttpsURLConnection;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.authenticator.voiceotp.VoiceOTPConstants.CHAR_SET_UTF_8;
import static org.wso2.carbon.identity.authenticator.voiceotp.VoiceOTPConstants.CONTENT_TYPE;
import static org.wso2.carbon.identity.authenticator.voiceotp.VoiceOTPConstants.ERROR_MESSAGE_DETAILS;
import static org.wso2.carbon.identity.authenticator.voiceotp.VoiceOTPConstants.JSON_CONTENT_TYPE;
import static org.wso2.carbon.identity.authenticator.voiceotp.VoiceOTPConstants.MASKING_VALUE_SEPARATOR;
import static org.wso2.carbon.identity.authenticator.voiceotp.VoiceOTPConstants.MOBILE_NUMBER_REGEX;
import static org.wso2.carbon.identity.authenticator.voiceotp.VoiceOTPConstants.POST_METHOD;
import static org.wso2.carbon.identity.authenticator.voiceotp.VoiceOTPConstants.RESEND;
import static org.wso2.carbon.identity.authenticator.voiceotp.VoiceOTPConstants.XML_CONTENT_TYPE;

import static java.util.Base64.getEncoder;
import static org.wso2.carbon.identity.authenticator.voiceotp.VoiceOTPConstants.REQUESTED_USER_MOBILE;

/**
 * Authenticator of Voice OTP
 */
public class VoiceOTPAuthenticator extends AbstractApplicationAuthenticator implements FederatedApplicationAuthenticator {

    private static final Log log = LogFactory.getLog(VoiceOTPAuthenticator.class);
    private static final String TRIGGER_VOICE_NOTIFICATION = "TRIGGER_VOICE_NOTIFICATION";

    /**
     * Check whether the authentication or logout request can be handled by the authenticator
     */
    @Override
    public boolean canHandle(HttpServletRequest request) {

        if (log.isDebugEnabled()) {
            log.debug("Inside VoiceOTPAuthenticator canHandle method and check the existence of mobile number and " +
                    "otp code");
        }
        return ((StringUtils.isNotEmpty(request.getParameter(VoiceOTPConstants.RESEND))
                && StringUtils.isEmpty(request.getParameter(VoiceOTPConstants.CODE)))
                || StringUtils.isNotEmpty(request.getParameter(VoiceOTPConstants.CODE))
                || StringUtils.isNotEmpty(request.getParameter(VoiceOTPConstants.MOBILE_NUMBER)));
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request,
                                           HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {
        // if the logout request comes, then no need to go through and complete the flow.
        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        } else if (StringUtils.isNotEmpty(request.getParameter(VoiceOTPConstants.MOBILE_NUMBER))) {
            // if the request comes with MOBILE_NUMBER, it will go through this flow.
            initiateAuthenticationRequest(request, response, context);
            return AuthenticatorFlowStatus.INCOMPLETE;
        } else if (StringUtils.isEmpty(request.getParameter(VoiceOTPConstants.CODE))) {
            // if the request comes with code, it will go through this flow.
            initiateAuthenticationRequest(request, response, context);
            publishPostVoiceOTPGeneratedEvent(request, context);
            if (context.getProperty(VoiceOTPConstants.AUTHENTICATION)
                    .equals(VoiceOTPConstants.AUTHENTICATOR_NAME)) {
                // if the request comes with authentication is VoiceOTP, it will go through this flow.
                return AuthenticatorFlowStatus.INCOMPLETE;
            } else {
                // if the request comes with authentication is basic, complete the flow.
                return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
            }
        } else if (Boolean.parseBoolean(request.getParameter(RESEND))) {
            AuthenticatorFlowStatus authenticatorFlowStatus = super.process(request, response, context);
            publishPostVoiceOTPGeneratedEvent(request, context);
            return authenticatorFlowStatus;
        } else {
            AuthenticatorFlowStatus authenticatorFlowStatus = super.process(request, response, context);
            publishPostVoiceOTPValidatedEvent(request, context);
            return authenticatorFlowStatus;
        }
    }

    /**
     * Initiate the authentication request.
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        try {
            String username;
            AuthenticatedUser authenticatedUser;
            String mobileNumber;
            String tenantDomain = context.getTenantDomain();
            context.setProperty(VoiceOTPConstants.AUTHENTICATION, VoiceOTPConstants.AUTHENTICATOR_NAME);
            if (!tenantDomain.equals(VoiceOTPConstants.SUPER_TENANT)) {
                IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, getName(), tenantDomain);
            }
            FederatedAuthenticatorUtil.setUsernameFromFirstStep(context);
            username = String.valueOf(context.getProperty(VoiceOTPConstants.USER_NAME));
            authenticatedUser = (AuthenticatedUser) context.getProperty(VoiceOTPConstants.AUTHENTICATED_USER);
            // find the authenticated user.
            if (authenticatedUser == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Authentication failed: Could not find the authenticated user. ");
                }
                throw new AuthenticationFailedException
                        ("Authentication failed: Cannot proceed further without identifying the user. ");
            }
            boolean isVoiceOTPMandatory = VoiceOTPUtils.isVoiceOTPMandatory(context);
            boolean isUserExists = FederatedAuthenticatorUtil.isUserExistInUserStore(username);
            String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                    context.getCallerSessionKey(), context.getContextIdentifier());
            // This multi option URI is used to navigate back to multi option page to select a different
            // authentication option from Voice OTP pages.
            String multiOptionURI = getMultiOptionURIQueryParam(request);
            if (StringUtils.isNotEmpty(multiOptionURI)) {
                queryParams += multiOptionURI;
            }
            String errorPage = getErrorPage(context);
            // Voice OTP authentication is mandatory and user doesn't disable Voice OTP claim in user's profile.
            if (isVoiceOTPMandatory) {
                if (log.isDebugEnabled()) {
                    log.debug("Voice OTP is mandatory. Hence processing in mandatory path");
                }
                processVoiceOTPMandatoryCase(context, request, response, queryParams, username, isUserExists);
            } else if (isUserExists && !VoiceOTPUtils.isVoiceOTPDisableForLocalUser(username, context)) {
                if ((context.isRetrying() && !Boolean.parseBoolean(request.getParameter(VoiceOTPConstants.RESEND))
                        && !isMobileNumberUpdateFailed(context)) || (VoiceOTPUtils.isLocalUser(context) &&
                        VoiceOTPUtils.isAccountLocked(authenticatedUser))) {
                    if (log.isDebugEnabled()) {
                        log.debug("Triggering Voice OTP retry flow");
                    }
                    checkStatusCode(response, context, queryParams, errorPage);
                } else {
                    mobileNumber = getMobileNumber(request, response, context, username, queryParams);
                    if (StringUtils.isNotEmpty(mobileNumber)) {
                        proceedWithOTP(response, context, errorPage, mobileNumber, queryParams, username);
                    }

                }
            } else {
                processFirstStepOnly(authenticatedUser, context);
            }
        } catch (VoiceOTPException e) {
            throw new AuthenticationFailedException("Failed to get the parameters from authentication xml file. ", e);
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Failed to get the user from User Store. ", e);
        }
    }

    /**
     * Get MultiOptionURI query parameter from the request.
     * @param request Http servlet request.
     * @return MultiOptionURI query parameter.
     */
    private String getMultiOptionURIQueryParam(HttpServletRequest request) {

        if (request != null) {
            String multiOptionURI = request.getParameter(VoiceOTPConstants.MULTI_OPTION_URI);
            if (StringUtils.isNotEmpty(multiOptionURI)) {
                return "&" + VoiceOTPConstants.MULTI_OPTION_URI + "="
                        + Encode.forUriComponent(multiOptionURI);
            }
        }
        return StringUtils.EMPTY;
    }

    /**
     * Get the mobile number from user's profile to send an otp.
     *
     * @param request     The HttpServletRequest.
     * @param response    The HttpServletResponse.
     * @param context     The AuthenticationContext.
     * @param username    The Username.
     * @param queryParams The queryParams.
     * @return the mobile number
     * @throws AuthenticationFailedException
     * @throws VoiceOTPException
     */
    private String getMobileNumber(HttpServletRequest request, HttpServletResponse response,
                                   AuthenticationContext context, String username,
                                   String queryParams) throws AuthenticationFailedException, VoiceOTPException {

        String mobileNumber = VoiceOTPUtils.getMobileNumberForUsername(username);
        if (StringUtils.isEmpty(mobileNumber)) {
            String requestMobile = request.getParameter(VoiceOTPConstants.MOBILE_NUMBER);
            if (StringUtils.isBlank(requestMobile) && !isMobileNumberUpdateFailed(context) && isCodeMismatch(context)) {
                mobileNumber = String.valueOf(context.getProperty(VoiceOTPConstants.REQUESTED_USER_MOBILE));
            } else if (StringUtils.isBlank(requestMobile)) {
                if (log.isDebugEnabled()) {
                    log.debug("User has not registered a mobile number: " + username);
                }
                redirectToMobileNoReqPage(response, context, queryParams);
            } else {
                context.setProperty(VoiceOTPConstants.REQUESTED_USER_MOBILE, requestMobile);
                mobileNumber = requestMobile;
            }
        }
        return mobileNumber;
    }

    /**
     * Get the loginPage from authentication.xml file or use the login page from constant file.
     *
     * @param context the AuthenticationContext
     * @return the loginPage
     * @throws AuthenticationFailedException
     */
    private String getLoginPage(AuthenticationContext context) throws AuthenticationFailedException {

        String loginPage = VoiceOTPUtils.getLoginPageFromXMLFile(context);
        if (StringUtils.isEmpty(loginPage)) {
            loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                    .replace(VoiceOTPConstants.LOGIN_PAGE, VoiceOTPConstants.VOICE_LOGIN_PAGE);
            if (log.isDebugEnabled()) {
                log.debug("Default authentication endpoint context is used");
            }
        }
        return loginPage;
    }

    /**
     * Get the errorPage from authentication.xml file or use the error page from constant file.
     *
     * @param context the AuthenticationContext
     * @return the errorPage
     * @throws AuthenticationFailedException
     */
    private String getErrorPage(AuthenticationContext context) throws AuthenticationFailedException {

        String errorPage = VoiceOTPUtils.getErrorPageFromXMLFile(context);
        if (StringUtils.isEmpty(errorPage)) {
            errorPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                    .replace(VoiceOTPConstants.LOGIN_PAGE, VoiceOTPConstants.ERROR_PAGE);
            if (log.isDebugEnabled()) {
                log.debug("Default authentication endpoint context is used");
            }
        }
        return errorPage;
    }

    /**
     * To get the redirection URL.
     *
     * @param baseURI     the base path
     * @param queryParams the queryParams
     * @return url
     */
    private String getURL(String baseURI, String queryParams) {

        String url;
        if (StringUtils.isNotEmpty(queryParams)) {
            url = baseURI + "?" + queryParams + "&" + VoiceOTPConstants.NAME_OF_AUTHENTICATORS + getName();
        } else {
            url = baseURI + "?" + VoiceOTPConstants.NAME_OF_AUTHENTICATORS + getName();
        }
        return url;
    }

    /**
     * Redirect to an error page.
     *
     * @param response    the HttpServletResponse
     * @param queryParams the queryParams
     * @throws AuthenticationFailedException
     */
    private void redirectToErrorPage(HttpServletResponse response, AuthenticationContext context, String queryParams,
                                     String retryParam)
            throws AuthenticationFailedException {
        // that Enable the Voice OTP in user's Profile. Cannot proceed further without Voice OTP authentication.
        try {
            String errorPage = getErrorPage(context);
            String url = getURL(errorPage, queryParams);
            response.sendRedirect(url + retryParam);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Exception occurred while redirecting to errorPage. ", e);
        }
    }

    /**
     * In VoiceOTP optional case proceed with first step only.It can be basic or federated.
     *
     * @param authenticatedUser the name of authenticatedUser
     * @param context           the AuthenticationContext
     */
    private void processFirstStepOnly(AuthenticatedUser authenticatedUser, AuthenticationContext context) {

        if (log.isDebugEnabled()) {
            log.debug("Processing First step only. Skipping VoiceOTP");
        }
        //the authentication flow happens with basic authentication.
        StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(context.getCurrentStep() - 1);
        if (stepConfig.getAuthenticatedAutenticator().getApplicationAuthenticator() instanceof
                LocalApplicationAuthenticator) {
            if (log.isDebugEnabled()) {
                log.debug("Found local authenticator in previous step. Hence setting a local user");
            }
            FederatedAuthenticatorUtil.updateLocalAuthenticatedUserInStepConfig(context, authenticatedUser);
            context.setProperty(VoiceOTPConstants.AUTHENTICATION, VoiceOTPConstants.BASIC);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Found federated authenticator in previous step. Hence setting a local user");
            }
            FederatedAuthenticatorUtil.updateAuthenticatedUserInStepConfig(context, authenticatedUser);
            context.setProperty(VoiceOTPConstants.AUTHENTICATION, VoiceOTPConstants.FEDERETOR);
        }
    }

    /**
     * Update mobile number when user forgets to update the mobile number in user's profile.
     *
     * @param context      the AuthenticationContext
     * @param request      the HttpServletRequest
     * @param username     the Username
     * @param tenantDomain the TenantDomain
     * @throws VoiceOTPException
     * @throws UserStoreException
     */
    private void updateMobileNumberForUsername(AuthenticationContext context, HttpServletRequest request,
                                               String username, String tenantDomain)
            throws VoiceOTPException, UserStoreException {

        if (log.isDebugEnabled()) {
            log.debug("Updating mobile number for user : " + username);
        }
        Map<String, String> attributes = new HashMap<>();
        attributes.put(VoiceOTPConstants.MOBILE_CLAIM, String.valueOf(context.getProperty(VoiceOTPConstants.REQUESTED_USER_MOBILE)));
        VoiceOTPUtils.updateUserAttribute(MultitenantUtils.getTenantAwareUsername(username), attributes,
                tenantDomain);
    }

    /**
     * Check with VoiceOTP mandatory case with VoiceOTP flow.
     *
     * @param context      the AuthenticationContext
     * @param request      the HttpServletRequest
     * @param response     the HttpServletResponse
     * @param queryParams  the queryParams
     * @param username     the Username
     * @param isUserExists check whether user exist or not
     * @throws AuthenticationFailedException
     * @throws VoiceOTPException
     */
    private void processVoiceOTPMandatoryCase(AuthenticationContext context, HttpServletRequest request,
                                              HttpServletResponse response, String queryParams, String username,
                                              boolean isUserExists) throws AuthenticationFailedException, VoiceOTPException {
        //the authentication flow happens with voice otp authentication.
        String tenantDomain = context.getTenantDomain();
        String errorPage = getErrorPage(context);
        if (context.isRetrying() && !Boolean.parseBoolean(request.getParameter(VoiceOTPConstants.RESEND))
                && !isMobileNumberUpdateFailed(context)) {
            if (log.isDebugEnabled()) {
                log.debug("Trigger retry flow when it is not request for resending OTP or it is not mobile number update failure");
            }
            checkStatusCode(response, context, queryParams, errorPage);
        } else {
            processVoiceOTPFlow(context, request, response, isUserExists, username, queryParams, tenantDomain,
                    errorPage);
        }
    }

    private void proceedOTPWithFederatedMobileNumber(AuthenticationContext context, HttpServletResponse response,
                                                     String username, String queryParams,
                                                     boolean sendOtpToFederatedMobile)
            throws AuthenticationFailedException {

        try {
            String federatedMobileAttributeKey;
            String mobile = null;
            StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(context.getCurrentStep() - 1);
            String previousStepAuthenticator = stepConfig.getAuthenticatedAutenticator().getName();
            StepConfig currentStep = context.getSequenceConfig().getStepMap().get(context.getCurrentStep());
            String currentStepAuthenticator = currentStep.getAuthenticatorList().iterator().next().getName();
            if (sendOtpToFederatedMobile) {
                federatedMobileAttributeKey = getFederatedMobileAttributeKey(context, previousStepAuthenticator);
                if (StringUtils.isEmpty(federatedMobileAttributeKey)) {
                    federatedMobileAttributeKey = getFederatedMobileAttributeKey(context, currentStepAuthenticator);
                }
                Map<ClaimMapping, String> userAttributes = context.getCurrentAuthenticatedIdPs().values().
                        iterator().next().getUser().getUserAttributes();
                for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
                    String key = String.valueOf(entry.getKey().getLocalClaim().getClaimUri());
                    String value = entry.getValue();
                    if (key.equals(federatedMobileAttributeKey)) {
                        mobile = String.valueOf(value);
                        proceedWithOTP(response, context, getErrorPage(context), mobile, queryParams, username);
                        break;
                    }
                }
                if (StringUtils.isEmpty(mobile)) {
                    if (log.isDebugEnabled()) {
                        log.debug("There is no mobile claim to send otp ");
                    }
                    throw new AuthenticationFailedException("There is no mobile claim to send otp");
                }
            } else {
                redirectToErrorPage(response, context, queryParams, VoiceOTPConstants.SEND_OTP_DIRECTLY_DISABLE);
            }
        } catch (AuthenticationFailedException e) {
            throw new AuthenticationFailedException(" Failed to process VoiceOTP flow ", e);
        }
    }

    private String getFederatedMobileAttributeKey(AuthenticationContext context, String authenticatorName) {

        String federatedVoiceAttributeKey = null;
        Map<String, String> parametersMap;
        String tenantDomain = context.getTenantDomain();
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        if (propertiesFromLocal != null || tenantDomain.equals(VoiceOTPConstants.SUPER_TENANT)) {
            parametersMap = FederatedAuthenticatorUtil.getAuthenticatorConfig(authenticatorName);
            if (parametersMap != null) {
                federatedVoiceAttributeKey = parametersMap.get
                        (VoiceOTPConstants.FEDERATED_MOBILE_ATTRIBUTE_KEY);
            }
        } else {
            federatedVoiceAttributeKey = String.valueOf(context.getProperty
                    (VoiceOTPConstants.FEDERATED_MOBILE_ATTRIBUTE_KEY));
        }
        return federatedVoiceAttributeKey;
    }

    /**
     * Check with VoiceOTP flow with user existence.
     *
     * @param context      the AuthenticationContext
     * @param request      the HttpServletRequest
     * @param response     the HttpServletResponse
     * @param isUserExists check whether user exist or not
     * @param username     the UserName
     * @param queryParams  the queryParams
     * @param tenantDomain the TenantDomain
     * @param errorPage    the errorPage
     * @throws AuthenticationFailedException
     * @throws VoiceOTPException
     */
    private void processVoiceOTPFlow(AuthenticationContext context, HttpServletRequest request,
                                     HttpServletResponse response, boolean isUserExists, String username,
                                     String queryParams, String tenantDomain, String errorPage)
            throws AuthenticationFailedException, VoiceOTPException {

        String mobileNumber = null;
        if (isUserExists) {
            boolean isVoiceOTPDisabledByUser = VoiceOTPUtils.isVoiceOTPDisableForLocalUser(username, context);
            if (log.isDebugEnabled()) {
                log.debug("Has user enabled Voice OTP : " + isVoiceOTPDisabledByUser);
            }
            if (isVoiceOTPDisabledByUser) {
                // that Enable the Voice OTP in user's Profile. Cannot proceed further without Voice OTP authentication.
                redirectToErrorPage(response, context, queryParams, VoiceOTPConstants.ERROR_VOICEOTP_DISABLE);
            } else {
                mobileNumber = getMobileNumber(request, response, context, username, queryParams);
            }
        } else if (VoiceOTPUtils.isSendOTPDirectlyToMobile(context)) {
            if (log.isDebugEnabled()) {
                log.debug("User :" + username + " doesn't exist");
            }
            if (request.getParameter(VoiceOTPConstants.MOBILE_NUMBER) == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Couldn't find the mobile number in request. Hence redirecting to mobile number input " +
                            "page");
                }
                String loginPage = VoiceOTPUtils.getMobileNumberRequestPage(context);
                try {
                    String url = getURL(loginPage, queryParams);
                    String mobileNumberPatternViolationError = VoiceOTPConstants.MOBILE_NUMBER_PATTERN_POLICY_VIOLATED;
                    String mobileNumberPattern =
                            context.getAuthenticatorProperties().get(VoiceOTPConstants.MOBILE_NUMBER_REGEX);
                    if (StringUtils.isNotEmpty(mobileNumberPattern)) {
                        // Check for regex is violation error message configured in idp configuration.
                        if (StringUtils.isNotEmpty(context.getAuthenticatorProperties()
                                .get(VoiceOTPConstants.MOBILE_NUMBER_PATTERN_FAILURE_ERROR_MESSAGE))) {
                            mobileNumberPatternViolationError = context.getAuthenticatorProperties()
                                    .get(VoiceOTPConstants.MOBILE_NUMBER_PATTERN_FAILURE_ERROR_MESSAGE);
                        }
                        // Send the response with encoded regex pattern and error message.
                        response.sendRedirect(FrameworkUtils
                                .appendQueryParamsStringToUrl(url, VoiceOTPConstants.MOBILE_NUMBER_REGEX_PATTERN_QUERY +
                                        getEncoder().encodeToString(context.getAuthenticatorProperties()
                                                .get(MOBILE_NUMBER_REGEX)
                                                .getBytes()) +
                                        VoiceOTPConstants.MOBILE_NUMBER_PATTERN_POLICY_FAILURE_ERROR_MESSAGE_QUERY +
                                        getEncoder().encodeToString(mobileNumberPatternViolationError.getBytes())));
                    } else {
                        response.sendRedirect(url);
                    }
                } catch (IOException e) {
                    throw new AuthenticationFailedException("Authentication failed!. An IOException occurred ", e);
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Mobile number found in request : " + request.getParameter(VoiceOTPConstants.MOBILE_NUMBER));
                }
                mobileNumber = request.getParameter(VoiceOTPConstants.MOBILE_NUMBER);
            }
        } else if (VoiceOTPUtils.sendOtpToFederatedMobile(context)) {
            if (log.isDebugEnabled()) {
                log.debug("Voice OTP is mandatory. But user is not there in active directory. Hence send the otp to the " +
                        "federated mobile claim");
            }
            proceedOTPWithFederatedMobileNumber(context, response, username, queryParams,
                    VoiceOTPUtils.sendOtpToFederatedMobile(context));
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Voice OTP is mandatory. But couldn't find a mobile number.");
            }
            redirectToErrorPage(response, context, queryParams, VoiceOTPConstants.SEND_OTP_DIRECTLY_DISABLE);
        }
        if (StringUtils.isNotEmpty(mobileNumber)) {
            proceedWithOTP(response, context, errorPage, mobileNumber, queryParams, username);
        }
    }

    /**
     * Proceed with One Time Password.
     *
     * @param response     the HttpServletResponse
     * @param context      the AuthenticationContext
     * @param errorPage    the errorPage
     * @param mobileNumber the mobile number
     * @param queryParams  the queryParams
     * @param username     the Username
     * @throws AuthenticationFailedException
     */
    private void proceedWithOTP(HttpServletResponse response, AuthenticationContext context, String errorPage,
                                String mobileNumber, String queryParams, String username)
            throws AuthenticationFailedException {

        String screenValue;
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        boolean isEnableResendCode = VoiceOTPUtils.isEnableResendCode(context);
        String loginPage = getLoginPage(context);
        String tenantDomain = MultitenantUtils.getTenantDomain(username);
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        UserRealm userRealm = VoiceOTPUtils.getUserRealm(tenantDomain);
        int tokenLength = VoiceOTPConstants.NUMBER_DIGIT;
        long otpValidityPeriod = VoiceOTPConstants.DEFAULT_VALIDITY_PERIOD;
        boolean isEnableAlphanumericToken = VoiceOTPUtils.isEnableAlphanumericToken(context);
        try {
            // One time password is generated and stored in the context.
            OneTimePassword token = new OneTimePassword();
            String secret = OneTimePassword.getRandomNumber(VoiceOTPConstants.SECRET_KEY_LENGTH);
            if ((VoiceOTPUtils.getTokenLength(context)) != null) {
                tokenLength = Integer.parseInt(VoiceOTPUtils.getTokenLength(context));
            }
            if ((VoiceOTPUtils.getTokenExpiryTime(context)) != null) {
                otpValidityPeriod = Integer.parseInt(VoiceOTPUtils.getTokenExpiryTime(context));
            }
            context.setProperty(VoiceOTPConstants.TOKEN_VALIDITY_TIME, otpValidityPeriod);
            String otpToken = token.generateToken(secret, String.valueOf(VoiceOTPConstants.NUMBER_BASE), tokenLength,
                    isEnableAlphanumericToken);
            context.setProperty(VoiceOTPConstants.OTP_TOKEN, otpToken);
            if (log.isDebugEnabled()) {
                log.debug("Generated OTP successfully and set to the context.");
            }

            if(VoiceOTPUtils.isOTPNumberSplitEnabled(context)){
                otpToken = VoiceOTPUtils.splitAndEncodeNumber(otpToken,1, context);
            }

            //Get the values of the voice provider related api parameters.
            String voiceUrl = authenticatorProperties.get(VoiceOTPConstants.VOICE_URL);
            String httpMethod = authenticatorProperties.get(VoiceOTPConstants.HTTP_METHOD);
            String headerString = authenticatorProperties.get(VoiceOTPConstants.HEADERS);
            String payload = authenticatorProperties.get(VoiceOTPConstants.PAYLOAD);
            String httpResponse = authenticatorProperties.get(VoiceOTPConstants.HTTP_RESPONSE);
            boolean connectionResult = true;
            //Check the Voice URL configure in UI and give the first priority for that.
            if (StringUtils.isNotEmpty(voiceUrl)) {
                connectionResult = sendRESTCall(context, voiceUrl, httpMethod, headerString, payload,
                        httpResponse, mobileNumber, otpToken);
            } else {
                //Use the default notification mechanism (CEP) to send Voice.
                AuthenticatedUser authenticatedUser = (AuthenticatedUser)
                        context.getProperty(VoiceOTPConstants.AUTHENTICATED_USER);
                String serviceProviderName = context.getServiceProviderName();
                triggerNotification(authenticatedUser.getUserName(), authenticatedUser.getTenantDomain(),
                        authenticatedUser.getUserStoreDomain(), mobileNumber, otpToken, serviceProviderName,
                        otpValidityPeriod);
            }

            if (!connectionResult) {
                String retryParam;
                if (context.getProperty(VoiceOTPConstants.ERROR_CODE) != null) {
                    String errorCode = context.getProperty(VoiceOTPConstants.ERROR_CODE).toString();
                    // If UseInternalErrorCodes is configured as true, then http response error codes will be mapped
                    // to local error codes and passed as query param value for authfailure msg.
                    if (VoiceOTPUtils.useInternalErrorCodes(context)) {
                        String errorResponseCode = getHttpErrorResponseCode(errorCode);
                        if (StringUtils.isNotEmpty(errorResponseCode)) {
                            String internalErrorCode = VoiceOTPConstants.ErrorMessage.
                                    getMappedInternalErrorCode(errorResponseCode).getCode();
                            errorCode = URLEncoder.encode(internalErrorCode, CHAR_SET_UTF_8);
                        }
                    }
                    retryParam = VoiceOTPConstants.ERROR_MESSAGE + errorCode;
                    String errorInfo = context.getProperty(VoiceOTPConstants.ERROR_INFO).toString();
                    if (Boolean.parseBoolean(authenticatorProperties.get(VoiceOTPConstants.SHOW_ERROR_INFO)) &&
                            errorInfo != null) {
                        retryParam = retryParam + VoiceOTPConstants.ERROR_MESSAGE_DETAILS + getEncoder().encodeToString
                                (errorInfo.getBytes());
                    }
                } else {
                    retryParam = VoiceOTPConstants.ERROR_MESSAGE + VoiceOTPConstants.UNABLE_SEND_CODE_VALUE;
                }
                String redirectUrl = getURL(errorPage, queryParams);
                response.sendRedirect(redirectUrl + VoiceOTPConstants.RESEND_CODE + isEnableResendCode + retryParam);
            } else {
                long sentOTPTokenTime = System.currentTimeMillis();
                context.setProperty(VoiceOTPConstants.SENT_OTP_TOKEN_TIME, sentOTPTokenTime);
                String url = getURL(loginPage, queryParams);
                boolean isUserExists = FederatedAuthenticatorUtil.isUserExistInUserStore(username);
                if (isUserExists) {
                    screenValue = getScreenAttribute(context, userRealm, tenantAwareUsername);
                    if (screenValue != null) {
                        url = url + VoiceOTPConstants.SCREEN_VALUE + screenValue;
                    }
                }
                response.sendRedirect(url);
            }
        } catch (IOException e) {
            throw new AuthenticationFailedException("Error while sending the HTTP request. ", e);
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Failed to get the user from user store. ", e);
        }
    }

    /**
     * Check the status codes when resend and retry enabled.
     *
     * @param response    the HttpServletResponse
     * @param context     the AuthenticationContext
     * @param queryParams the queryParams
     * @param errorPage   the errorPage
     * @throws AuthenticationFailedException
     */
    private void checkStatusCode(HttpServletResponse response, AuthenticationContext context,
                                 String queryParams, String errorPage) throws AuthenticationFailedException {

        boolean isRetryEnabled = VoiceOTPUtils.isRetryEnabled(context);
        String loginPage = getLoginPage(context);
        AuthenticatedUser authenticatedUser =
                (AuthenticatedUser) context.getProperty(VoiceOTPConstants.AUTHENTICATED_USER);
        String url = getURL(loginPage, queryParams);
        if (StringUtils.isNotEmpty(getScreenValue(context))) {
            url = url + VoiceOTPConstants.SCREEN_VALUE + getScreenValue(context);
        }
        try {
            if (VoiceOTPUtils.isLocalUser(context) && VoiceOTPUtils.isAccountLocked(authenticatedUser)) {
                boolean showAuthFailureReason = VoiceOTPUtils.isShowAuthFailureReason(context);
                String retryParam;
                if (showAuthFailureReason) {
                    long unlockTime = getUnlockTimeInMilliSeconds(authenticatedUser);
                    long timeToUnlock = unlockTime - System.currentTimeMillis();
                    if (timeToUnlock > 0) {
                        queryParams += "&unlockTime=" + Math.round((double) timeToUnlock / 1000 / 60);
                    }
                    retryParam = VoiceOTPConstants.ERROR_USER_ACCOUNT_LOCKED;
                } else {
                    retryParam = VoiceOTPConstants.RETRY_PARAMS;
                }
                redirectToErrorPage(response, context, queryParams, retryParam);
            } else if (isRetryEnabled) {
                if (StringUtils.isNotEmpty((String) context.getProperty(VoiceOTPConstants.TOKEN_EXPIRED))) {
                    response.sendRedirect(url + VoiceOTPConstants.RESEND_CODE
                            + VoiceOTPUtils.isEnableResendCode(context) + VoiceOTPConstants.ERROR_MESSAGE +
                            VoiceOTPConstants.TOKEN_EXPIRED_VALUE);
                } else {
                    response.sendRedirect(url + VoiceOTPConstants.RESEND_CODE
                            + VoiceOTPUtils.isEnableResendCode(context) + VoiceOTPConstants.RETRY_PARAMS);
                }
            } else {
                url = getURL(errorPage, queryParams);
                if (Boolean.parseBoolean(String.valueOf(context.getProperty(VoiceOTPConstants.CODE_MISMATCH)))) {
                    response.sendRedirect(url + VoiceOTPConstants.RESEND_CODE
                            + VoiceOTPUtils.isEnableResendCode(context) + VoiceOTPConstants.ERROR_MESSAGE
                            + VoiceOTPConstants.ERROR_CODE_MISMATCH);
                } else if (StringUtils.isNotEmpty((String) context.getProperty(VoiceOTPConstants.TOKEN_EXPIRED))) {
                    response.sendRedirect(url + VoiceOTPConstants.RESEND_CODE
                            + VoiceOTPUtils.isEnableResendCode(context) + VoiceOTPConstants.ERROR_MESSAGE + VoiceOTPConstants
                            .TOKEN_EXPIRED_VALUE);
                } else {
                    response.sendRedirect(url + VoiceOTPConstants.RESEND_CODE
                            + VoiceOTPUtils.isEnableResendCode(context) + VoiceOTPConstants.RETRY_PARAMS);
                }
            }
        } catch (IOException e) {
            throw new AuthenticationFailedException("Authentication Failed: An IOException was caught. ", e);
        }
    }

    /**
     * Get the screen value for configured screen attribute.
     *
     * @param context the AuthenticationContext
     * @return screenValue
     * @throws AuthenticationFailedException
     */
    private String getScreenValue(AuthenticationContext context) throws AuthenticationFailedException {

        String screenValue;
        String username = String.valueOf(context.getProperty(VoiceOTPConstants.USER_NAME));
        String tenantDomain = MultitenantUtils.getTenantDomain(username);
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        UserRealm userRealm = VoiceOTPUtils.getUserRealm(tenantDomain);
        try {
            screenValue = getScreenAttribute(context, userRealm, tenantAwareUsername);
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Failed to get the screen attribute for the user " +
                    tenantAwareUsername + " from user store. ", e);
        }
        return screenValue;
    }

    /**
     * Redirect the user to mobile number request page.
     *
     * @param response    the HttpServletResponse
     * @param context     the AuthenticationContext
     * @param queryParams the queryParams
     * @throws AuthenticationFailedException
     */
    private void redirectToMobileNoReqPage(HttpServletResponse response, AuthenticationContext context,
                                           String queryParams) throws AuthenticationFailedException {

        boolean isEnableMobileNoUpdate = VoiceOTPUtils.isEnableMobileNoUpdate(context);
        if (isEnableMobileNoUpdate) {
            String loginPage = VoiceOTPUtils.getMobileNumberRequestPage(context);
            try {
                String url = getURL(loginPage, queryParams);
                if (log.isDebugEnabled()) {
                    log.debug("Redirecting to mobile number request page : " + url);
                }
                String mobileNumberPatternViolationError = VoiceOTPConstants.MOBILE_NUMBER_PATTERN_POLICY_VIOLATED;
                String mobileNumberPattern =
                        context.getAuthenticatorProperties().get(VoiceOTPConstants.MOBILE_NUMBER_REGEX);
                if (isMobileNumberUpdateFailed(context)) {
                    url = FrameworkUtils.appendQueryParamsStringToUrl(url, VoiceOTPConstants.RETRY_PARAMS);
                    if (context.getProperty(VoiceOTPConstants.PROFILE_UPDATE_FAILURE_REASON) != null) {
                        String failureReason = String.valueOf(
                                context.getProperty(VoiceOTPConstants.PROFILE_UPDATE_FAILURE_REASON));
                        String urlEncodedFailureReason = URLEncoder.encode(failureReason, CHAR_SET_UTF_8);
                        String failureQueryParam = ERROR_MESSAGE_DETAILS + urlEncodedFailureReason;
                        url = FrameworkUtils.appendQueryParamsStringToUrl(url, failureQueryParam);
                    }
                }
                if (StringUtils.isNotEmpty(mobileNumberPattern)) {
                    // Check for regex is violation error message configured in idp configuration.
                    if (StringUtils.isNotEmpty(context.getAuthenticatorProperties()
                            .get(VoiceOTPConstants.MOBILE_NUMBER_PATTERN_FAILURE_ERROR_MESSAGE))) {
                        mobileNumberPatternViolationError = context.getAuthenticatorProperties()
                                .get(VoiceOTPConstants.MOBILE_NUMBER_PATTERN_FAILURE_ERROR_MESSAGE);
                    }
                    // Send the response with encoded regex pattern and error message.
                    response.sendRedirect(FrameworkUtils
                            .appendQueryParamsStringToUrl(url, VoiceOTPConstants.MOBILE_NUMBER_REGEX_PATTERN_QUERY +
                                    getEncoder().encodeToString(context.getAuthenticatorProperties()
                                            .get(VoiceOTPConstants.MOBILE_NUMBER_REGEX)
                                            .getBytes()) +
                                    VoiceOTPConstants.MOBILE_NUMBER_PATTERN_POLICY_FAILURE_ERROR_MESSAGE_QUERY +
                                    getEncoder().encodeToString(mobileNumberPatternViolationError.getBytes())));
                } else {
                    response.sendRedirect(url);
                }
            } catch (IOException e) {
                throw new AuthenticationFailedException("Authentication failed!. An IOException was caught. ", e);
            }
        } else {
            throw new AuthenticationFailedException("Authentication failed!. Update mobile no in your profile.");
        }
    }

    /**
     * Process the response of the VoiceOTP end-point.
     *
     * @param request  the HttpServletRequest
     * @param response the HttpServletResponse
     * @param context  the AuthenticationContext
     * @throws AuthenticationFailedException
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        AuthenticatedUser authenticatedUser = getAuthenticatedUser(context);
        boolean isLocalUser = VoiceOTPUtils.isLocalUser(context);

        if (authenticatedUser != null && isLocalUser && VoiceOTPUtils.isAccountLocked(authenticatedUser)) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Authentication failed since authenticated user: %s,  account is locked.",
                        authenticatedUser));
            }
            context.setProperty(VoiceOTPConstants.ACCOUNT_LOCKED, true);
            throw new AuthenticationFailedException("User account is locked.");
        }

        String userToken = request.getParameter(VoiceOTPConstants.CODE);
        String contextToken = (String) context.getProperty(VoiceOTPConstants.OTP_TOKEN);
        if (StringUtils.isEmpty(request.getParameter(VoiceOTPConstants.CODE))) {
            throw new InvalidCredentialsException("Code cannot not be null");
        }
        if (Boolean.parseBoolean(request.getParameter(VoiceOTPConstants.RESEND))) {
            if (log.isDebugEnabled()) {
                log.debug("Retrying to resend the OTP");
            }
            throw new InvalidCredentialsException("Retrying to resend the OTP");
        }

        if (context.getProperty(VoiceOTPConstants.MOBILE_NUMBER_UPDATE_FAILURE) != null) {
            context.setProperty(VoiceOTPConstants.MOBILE_NUMBER_UPDATE_FAILURE, "false");
        }

        boolean succeededAttempt = false;
        if (userToken.equals(contextToken)) {
            context.removeProperty(VoiceOTPConstants.CODE_MISMATCH);
            processValidUserToken(context, authenticatedUser);
            succeededAttempt = true;
        } else if (isLocalUser && "true".equals(VoiceOTPUtils.getBackupCode(context))) {
            succeededAttempt = checkWithBackUpCodes(context, userToken, authenticatedUser);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Given otp code is a mismatch.");
            }
            context.setProperty(VoiceOTPConstants.CODE_MISMATCH, true);
        }

        if (succeededAttempt && isLocalUser) {
            String username = String.valueOf(context.getProperty(VoiceOTPConstants.USER_NAME));
            String mobileNumber;
            try {
                mobileNumber = VoiceOTPUtils.getMobileNumberForUsername(username);
            } catch (VoiceOTPException e) {
                throw new AuthenticationFailedException("Failed to get the parameters from authentication xml file " +
                        "for user:  " + username + " for tenant: " + context.getTenantDomain(), e);
            }

            if (StringUtils.isBlank(mobileNumber)) {
                String tenantDomain = MultitenantUtils.getTenantDomain(username);
                Object verifiedMobileObject = context.getProperty(VoiceOTPConstants.REQUESTED_USER_MOBILE);
                if (verifiedMobileObject != null) {
                    try {
                        updateMobileNumberForUsername(context, request, username, tenantDomain);
                    } catch (VoiceOTPException e) {
                        throw new AuthenticationFailedException("Failed accessing the userstore for user: " + username, e.getCause());
                    } catch (UserStoreClientException e) {
                        context.setProperty(VoiceOTPConstants.MOBILE_NUMBER_UPDATE_FAILURE, "true");
                        throw new AuthenticationFailedException("Mobile claim update failed for user :" + username, e);
                    } catch (UserStoreException e) {
                        Throwable ex = e.getCause();
                        if (ex instanceof UserStoreClientException) {
                            context.setProperty(VoiceOTPConstants.MOBILE_NUMBER_UPDATE_FAILURE, "true");
                            context.setProperty(VoiceOTPConstants.PROFILE_UPDATE_FAILURE_REASON, ex.getMessage());
                        }
                        throw new AuthenticationFailedException("Mobile claim update failed for user " + username, e);
                    }
                }
            }
        }

        if (!succeededAttempt) {
            handleVoiceOtpVerificationFail(context);
            context.setProperty(VoiceOTPConstants.CODE_MISMATCH, true);
            throw new AuthenticationFailedException("Invalid code. Verification failed.");
        }
        // It reached here means the authentication was successful.
        resetVoiceOtpFailedAttempts(context);
    }

    private void processValidUserToken(AuthenticationContext context, AuthenticatedUser authenticatedUser) throws
            AuthenticationFailedException {
        Optional<Object> tokenValidityTime = Optional.ofNullable(context.getProperty(VoiceOTPConstants.
                TOKEN_VALIDITY_TIME));
        if (!tokenValidityTime.isPresent() || !NumberUtils.isNumber(tokenValidityTime.get().toString())) {
            log.error("TokenExpiryTime property is not configured in application-authentication.xml or Voice OTP " +
                    "Authenticator UI");
            context.setSubject(authenticatedUser);
            return;
        }

        Optional<Object> otpTokenSentTime = Optional.ofNullable(context.getProperty(VoiceOTPConstants.
                SENT_OTP_TOKEN_TIME));
        if (!otpTokenSentTime.isPresent() || !NumberUtils.isNumber(otpTokenSentTime.get().toString())) {
            if (log.isDebugEnabled()) {
                log.debug("Could not find OTP sent time");
            }
            throw new AuthenticationFailedException("Internal Error Occurred");
        }

        long elapsedTokenTime = System.currentTimeMillis() - Long.parseLong(otpTokenSentTime.get().toString());

        if (elapsedTokenTime <= (Long.parseLong(tokenValidityTime.get().toString()) * 1000)) {
            context.removeProperty(VoiceOTPConstants.TOKEN_EXPIRED);
            context.setSubject(authenticatedUser);
        } else {
            context.setProperty(VoiceOTPConstants.TOKEN_EXPIRED, VoiceOTPConstants.TOKEN_EXPIRED_VALUE);
            handleVoiceOtpVerificationFail(context);
            throw new AuthenticationFailedException("OTP code has expired");
        }
    }

    /**
     * If user forgets the mobile, then user can use the back up codes to authenticate the user.
     * Check whether the entered code matches with a backup code.
     *
     * @param context           The AuthenticationContext.
     * @param userToken         The userToken.
     * @param authenticatedUser The authenticatedUser.
     * @return True if the user entered code matches with a backup code.
     * @throws AuthenticationFailedException If an error occurred while retrieving user claim for OTP list.
     */
    private boolean checkWithBackUpCodes(AuthenticationContext context, String userToken,
                                         AuthenticatedUser authenticatedUser) throws AuthenticationFailedException {

        boolean isMatchingToken = false;
        String[] savedOTPs = null;
        String username = context.getProperty(VoiceOTPConstants.USER_NAME).toString();
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        UserRealm userRealm = getUserRealm(username);
        try {
            if (userRealm != null) {
                UserStoreManager userStoreManager = userRealm.getUserStoreManager();
                if (userStoreManager != null) {
                    String savedOTPString = userStoreManager
                            .getUserClaimValue(tenantAwareUsername, VoiceOTPConstants.SAVED_OTP_LIST, null);
                    if (StringUtils.isNotEmpty(savedOTPString)) {
                        savedOTPs = savedOTPString.split(",");
                    }
                }
            }
            // Check whether there is any backup OTPs and return.
            if (ArrayUtils.isEmpty(savedOTPs)) {
                if (log.isDebugEnabled()) {
                    log.debug("The claim " + VoiceOTPConstants.SAVED_OTP_LIST + " does not contain any values");
                }
                return false;
            }
            if (isBackUpCodeValid(savedOTPs, userToken)) {
                if (log.isDebugEnabled()) {
                    log.debug("Found saved backup Voice OTP for user :" + authenticatedUser);
                }
                isMatchingToken = true;
                context.setSubject(authenticatedUser);
                savedOTPs = (String[]) ArrayUtils.removeElement(savedOTPs, userToken);
                userRealm.getUserStoreManager().setUserClaimValue(tenantAwareUsername,
                        VoiceOTPConstants.SAVED_OTP_LIST, String.join(",", savedOTPs), null);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("User entered OTP :" + userToken + " does not match with any of the saved " +
                            "backup codes");
                }
                context.setProperty(VoiceOTPConstants.CODE_MISMATCH, true);
            }
        } catch (UserStoreException e) {
            log.error("Cannot find the user claim for OTP list for user : " + authenticatedUser, e);
        }
        return isMatchingToken;
    }

    private boolean isBackUpCodeValid(String[] savedOTPs, String userToken) {

        if (StringUtils.isEmpty(userToken)) {
            return false;
        }
        // Check whether the usertoken exists in the saved backup OTP list.
        for (String value : savedOTPs) {
            if (value.equals(userToken))
                return true;
        }
        return false;
    }

    /**
     * Returns AuthenticatedUser object from context.
     *
     * @param context AuthenticationContext.
     * @return AuthenticatedUser
     */
    private AuthenticatedUser getAuthenticatedUser(AuthenticationContext context) {

        AuthenticatedUser authenticatedUser = null;
        Map<Integer, StepConfig> stepConfigMap = context.getSequenceConfig().getStepMap();
        for (StepConfig stepConfig : stepConfigMap.values()) {
            AuthenticatedUser authenticatedUserInStepConfig = stepConfig.getAuthenticatedUser();
            if (stepConfig.isSubjectAttributeStep() && authenticatedUserInStepConfig != null) {
                // Make a copy of the user from the subject attribute step as we might modify this within
                // the authenticator.
                authenticatedUser = new AuthenticatedUser(authenticatedUserInStepConfig);
                break;
            }
        }
        return authenticatedUser;
    }

    /**
     * Get the user realm of the logged in user.
     *
     * @param username the Username
     * @return the userRealm
     * @throws AuthenticationFailedException
     */
    private UserRealm getUserRealm(String username) throws AuthenticationFailedException {

        UserRealm userRealm = null;
        try {
            if (StringUtils.isNotEmpty(username)) {
                String tenantDomain = MultitenantUtils.getTenantDomain(username);
                int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
                RealmService realmService = IdentityTenantUtil.getRealmService();
                userRealm = realmService.getTenantUserRealm(tenantId);
            }
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Cannot find the user realm. ", e);
        }
        return userRealm;
    }

    /**
     * Get the user realm of the logged in user.
     *
     * @param authenticatedUser Authenticated user.
     * @return The userRealm.
     * @throws AuthenticationFailedException Exception on authentication failure.
     */
    private UserRealm getUserRealm(AuthenticatedUser authenticatedUser) throws AuthenticationFailedException {

        UserRealm userRealm = null;
        try {
            if (authenticatedUser != null) {
                String tenantDomain = authenticatedUser.getTenantDomain();
                int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
                RealmService realmService = IdentityTenantUtil.getRealmService();
                userRealm = realmService.getTenantUserRealm(tenantId);
            }
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Cannot find the user realm.", e);
        }
        return userRealm;
    }

    /**
     * Get the friendly name of the Authenticator
     */
    public String getFriendlyName() {

        return VoiceOTPConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get the name of the Authenticator
     */
    public String getName() {

        return VoiceOTPConstants.AUTHENTICATOR_NAME;
    }

    /**
     * Get the Context identifier sent with the request.
     */
    public String getContextIdentifier(HttpServletRequest httpServletRequest) {

        return httpServletRequest.getParameter(FrameworkConstants.SESSION_DATA_KEY);
    }

    @Override
    protected boolean retryAuthenticationEnabled() {

        return true;
    }

    /**
     * Get the configuration properties of UI
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<Property>();

        Property voiceUrl = new Property();
        voiceUrl.setName(VoiceOTPConstants.VOICE_URL);
        voiceUrl.setDisplayName("Voice URL");
        voiceUrl.setRequired(false);
        voiceUrl.setDescription("Enter client voice url value. If the phone number and text message are in URL, " +
                "specify them as $ctx.num and $ctx.msg or $ctx.otp");
        voiceUrl.setDisplayOrder(0);
        configProperties.add(voiceUrl);

        Property httpMethod = new Property();
        httpMethod.setName(VoiceOTPConstants.HTTP_METHOD);
        httpMethod.setDisplayName("HTTP Method");
        httpMethod.setRequired(false);
        httpMethod.setDescription("Enter the HTTP Method used by the Voice API");
        httpMethod.setDisplayOrder(1);
        configProperties.add(httpMethod);

        Property headers = new Property();
        headers.setName(VoiceOTPConstants.HEADERS);
        headers.setDisplayName("HTTP Headers");
        headers.setRequired(false);
        headers.setDescription("Enter the headers used by the API separated by comma, with the Header name and value " +
                "separated by \":\". If the phone number and text message are in Headers, specify them as $ctx.num " +
                "and $ctx.msg or $ctx.otp");
        headers.setDisplayOrder(2);
        configProperties.add(headers);

        Property payload = new Property();
        payload.setName(VoiceOTPConstants.PAYLOAD);
        payload.setDisplayName("HTTP Payload");
        payload.setRequired(false);
        payload.setDescription("Enter the HTTP Payload used by the Voice API. If the phone number and text message are " +
                "in Payload, specify them as $ctx.num and $ctx.msg or $ctx.otp");
        payload.setDisplayOrder(3);
        configProperties.add(payload);

        Property httpResponse = new Property();
        httpResponse.setName(VoiceOTPConstants.HTTP_RESPONSE);
        httpResponse.setDisplayName("HTTP Response Code");
        httpResponse.setRequired(false);
        httpResponse.setDescription("Enter the HTTP response code the API sends upon successful call. Leave empty if unknown");
        httpResponse.setDisplayOrder(4);
        configProperties.add(httpResponse);

        Property otpSeparator = new Property();
        otpSeparator.setName(VoiceOTPConstants.OTP_NUMBER_SPLIT_ENABLED);
        otpSeparator.setDisplayName("Enable OTP Separation");
        otpSeparator.setRequired(false);
        otpSeparator.setDescription("Enable this if the otp separation is required, which will separate the digits and reads digits separately during the call ");
        otpSeparator.setDefaultValue("TRUE");
        otpSeparator.setType("Boolean");
        otpSeparator.setDisplayOrder(5);
        configProperties.add(otpSeparator);

        Property otpDigitSeparator = new Property();
        otpDigitSeparator.setName(VoiceOTPConstants.OTP_SEPARATOR);
        otpDigitSeparator.setDisplayName("Separate OTP Digits");
        otpDigitSeparator.setRequired(false);
        otpDigitSeparator.setDescription("If the OTP separation is enabled, this will be use to separate the Digits of the OTP. This might differ from the OTP provider");
        otpDigitSeparator.setDisplayOrder(6);
        otpDigitSeparator.setDefaultValue(VoiceOTPConstants.DEFAULT_OTP_SEPARATOR);
        configProperties.add(otpDigitSeparator);

        Property showErrorInfo = new Property();
        showErrorInfo.setName(VoiceOTPConstants.SHOW_ERROR_INFO);
        showErrorInfo.setDisplayName("Show Detailed Error Information");
        showErrorInfo.setRequired(false);
        showErrorInfo.setDescription("Enter \"true\" if detailed error information from Voice provider needs to be " +
                "displayed in the UI");
        showErrorInfo.setDisplayOrder(7);
        configProperties.add(showErrorInfo);

        Property valuesToBeMasked = new Property();
        valuesToBeMasked.setName(VoiceOTPConstants.VALUES_TO_BE_MASKED_IN_ERROR_INFO);
        valuesToBeMasked.setDisplayName("Mask values in Error Info");
        valuesToBeMasked.setRequired(false);
        valuesToBeMasked.setDescription("Enter comma separated Values to be masked by * in the detailed error messages");
        valuesToBeMasked.setDisplayOrder(8);
        configProperties.add(valuesToBeMasked);

        Property mobileNumberRegex = new Property();
        mobileNumberRegex.setName(VoiceOTPConstants.MOBILE_NUMBER_REGEX);
        mobileNumberRegex.setDisplayName("Mobile Number Regex Pattern");
        mobileNumberRegex.setRequired(false);
        mobileNumberRegex.setDescription("Enter regex format to validate mobile number while capture and update " +
                "mobile number.");
        mobileNumberRegex.setDisplayOrder(9);
        configProperties.add(mobileNumberRegex);

        Property RegexFailureErrorMessage = new Property();
        RegexFailureErrorMessage.setName(VoiceOTPConstants.MOBILE_NUMBER_PATTERN_FAILURE_ERROR_MESSAGE);
        RegexFailureErrorMessage.setDisplayName("Regex Violation Error Message");
        RegexFailureErrorMessage.setRequired(false);
        RegexFailureErrorMessage.setDescription("Enter error message for invalid mobile number patterns.");
        RegexFailureErrorMessage.setDisplayOrder(10);
        configProperties.add(RegexFailureErrorMessage);

        return configProperties;
    }

    /**
     * Get the connection and proceed with Voice API rest call.
     *
     * @param httpConnection       The connection.
     * @param context              The authenticationContext.
     * @param headerString         The header string.
     * @param payload              The payload.
     * @param httpResponse         The http response.
     * @param receivedMobileNumber The encoded mobileNo.
     * @param voiceMessage           The voice message.
     * @param otpToken             The token.
     * @param httpMethod           The http method.
     * @return true or false
     * @throws AuthenticationFailedException
     */
    private boolean getConnection(HttpURLConnection httpConnection, AuthenticationContext context, String headerString,
                                  String payload, String httpResponse, String receivedMobileNumber, String voiceMessage,
                                  String otpToken, String httpMethod) throws AuthenticationFailedException {

        try {
            httpConnection.setDoInput(true);
            httpConnection.setDoOutput(true);
            String encodedMobileNo = URLEncoder.encode(receivedMobileNumber, CHAR_SET_UTF_8);
            String encodedVoiceMessage;
            String[] headerArray;
            HashMap<String, Object> headerElementProperties = new HashMap<>();
            if (StringUtils.isNotEmpty(headerString)) {
                if (log.isDebugEnabled()) {
                    log.debug("Processing HTTP headers since header string is available");
                }
                headerString = headerString.trim().replaceAll("\\$ctx.num", receivedMobileNumber).replaceAll(
                        "\\$ctx.msg", voiceMessage + otpToken);
                headerArray = headerString.split(",");
                for (String header : headerArray) {
                    String[] headerElements = header.split(":", 2);
                    if (headerElements.length > 1) {
                        httpConnection.setRequestProperty(headerElements[0], headerElements[1]);
                        headerElementProperties.put(headerElements[0], headerElements[1]);
                    } else {
                        log.info("Either header name or value not found. Hence not adding header which contains " +
                                headerElements[0]);
                    }
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("No configured headers found. Header string is empty");
                }
            }

            // Processing HTTP Method
            if (log.isDebugEnabled()) {
                log.debug("Configured http method is " + httpMethod);
            }

            if (VoiceOTPConstants.GET_METHOD.equalsIgnoreCase(httpMethod)) {
                httpConnection.setRequestMethod(VoiceOTPConstants.GET_METHOD);

            } else if (VoiceOTPConstants.POST_METHOD.equalsIgnoreCase(httpMethod)) {
                httpConnection.setRequestMethod(VoiceOTPConstants.POST_METHOD);
                if (StringUtils.isNotEmpty(payload)) {
                    String contentType =
                            StringUtils.trimToEmpty((String) headerElementProperties.get(CONTENT_TYPE));
                    /*
                    If the enable_payload_encoding_for_voice_otp configuration is disabled, mobile number in the
                    payload will be URL encoded for all the content-types except for application/json content type
                    preserving the previous implementation to support backward compatibility.
                    */
                    if (VoiceOTPUtils.isPayloadEncodingForVoiceOTPEnabled(context)) {
                        /*
                        here only the mobile number and Voice message will be encoded, assuming the rest of the content is
                        in correct format.
                        */
                        encodedMobileNo = getEncodedValue(contentType, receivedMobileNumber);
                        encodedVoiceMessage = getEncodedValue(contentType, voiceMessage);
                    } else {
                        encodedVoiceMessage = voiceMessage;
                        if (StringUtils.isNotBlank(contentType) && POST_METHOD.equals(httpMethod) &&
                                (JSON_CONTENT_TYPE).equals(contentType)) {
                            encodedMobileNo = receivedMobileNumber;
                        }
                    }
                    payload = payload.replaceAll("\\$ctx.num", encodedMobileNo).replaceAll("\\$ctx.msg",
                            encodedVoiceMessage + otpToken).replaceAll("\\$ctx.otp",otpToken);
                    OutputStreamWriter writer = null;
                    try {
                        writer = new OutputStreamWriter(httpConnection.getOutputStream(), VoiceOTPConstants.CHAR_SET_UTF_8);
                        writer.write(payload);
                    } catch (IOException e) {
                        throw new AuthenticationFailedException("Error while posting payload message ", e);
                    } finally {
                        if (writer != null) {
                            writer.close();
                        }
                    }
                }
            }
            if (StringUtils.isNotEmpty(httpResponse)) {
                if (httpResponse.trim().equals(String.valueOf(httpConnection.getResponseCode()))) {
                    if (log.isDebugEnabled()) {
                        log.debug("Code is successfully sent to the mobile and received expected response code : " +
                                httpResponse);
                    }
                    return true;
                } else {
                    log.error("Error while sending Voice: error code is " + httpConnection.getResponseCode()
                            + " and error message is " + httpConnection.getResponseMessage());
                }
            } else {
                if (httpConnection.getResponseCode() == 200 || httpConnection.getResponseCode() == 201
                        || httpConnection.getResponseCode() == 202) {
                    if (log.isDebugEnabled()) {
                        log.debug("Code is successfully sent to the mobile. Relieved HTTP response code is : " +
                                httpConnection.getResponseCode());
                    }
                    return true;
                } else {
                    context.setProperty(VoiceOTPConstants.ERROR_CODE, httpConnection.getResponseCode() + " : " +
                            httpConnection.getResponseMessage());
                    if (httpConnection.getErrorStream() != null) {
                        String content = getSanitizedErrorInfo(httpConnection.getErrorStream(), context, encodedMobileNo);

                        log.error("Error while sending Voice: error code is " + httpConnection.getResponseCode()
                                + " and error message is " + httpConnection.getResponseMessage());
                        context.setProperty(VoiceOTPConstants.ERROR_INFO, content);
                    }
                    return false;
                }
            }
        } catch (MalformedURLException e) {
            throw new AuthenticationFailedException("Invalid URL ", e);
        } catch (ProtocolException e) {
            throw new AuthenticationFailedException("Error while setting the HTTP method ", e);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Error while setting the HTTP response ", e);
        } finally {
            if (httpConnection != null) {
                httpConnection.disconnect();
            }
        }
        return false;
    }


    private String getSanitizedErrorInfo(InputStream errorStream, AuthenticationContext context, String
            encodedMobileNo) throws IOException, AuthenticationFailedException {

        String contentRaw = readContent(errorStream);

        String screenValue = getScreenValue(context);
        if (StringUtils.isEmpty(screenValue)) {
            int noOfDigits = 0;
            if ((VoiceOTPUtils.getNoOfDigits(context)) != null) {
                noOfDigits = Integer.parseInt(VoiceOTPUtils.getNoOfDigits(context));
            }
            screenValue = getMaskedValue(context, encodedMobileNo, noOfDigits);
        }
        String content = contentRaw.replace(encodedMobileNo, screenValue);
        String decodedMobileNo = URLDecoder.decode(encodedMobileNo);
        content = content.replace(decodedMobileNo, screenValue);
        content = maskConfiguredValues(context, content);
        context.setProperty(VoiceOTPConstants.ERROR_INFO, content);

        String errorContent = content;
        if (log.isDebugEnabled()) {
            errorContent = contentRaw;
        }
        log.error(String.format("Following Error occurred while sending Voice for user: %s, %s", String.valueOf(context
                .getProperty(VoiceOTPConstants.USER_NAME)), errorContent));

        return content;
    }

    private String maskConfiguredValues(AuthenticationContext context, String content) {

        String valuesToMask = context.getAuthenticatorProperties().get(VoiceOTPConstants
                .VALUES_TO_BE_MASKED_IN_ERROR_INFO);
        if (StringUtils.isNotEmpty(valuesToMask)) {
            String[] values = valuesToMask.split(MASKING_VALUE_SEPARATOR);
            for (String val : values) {
                content = content.replaceAll(val, getMaskedValue(context, val, 0));
            }

        }
        return content;
    }

    private String readContent(InputStream errorStream) throws IOException {

        BufferedReader br = new BufferedReader(new InputStreamReader(errorStream));
        StringBuilder sb = new StringBuilder();
        String output;
        while ((output = br.readLine()) != null) {
            sb.append(output);
        }
        return sb.toString();
    }

    /**
     * Proceed with Voice API's rest call.
     *
     * @param context      the AuthenticationContext
     * @param voiceUrl       the voiceUrl
     * @param httpMethod   the httpMethod
     * @param headerString the headerString
     * @param payload      the payload
     * @param httpResponse the httpResponse
     * @param mobile       the mobile number
     * @param otpToken     the OTP token
     * @return true or false
     * @throws IOException
     * @throws AuthenticationFailedException
     */
    public boolean sendRESTCall(AuthenticationContext context, String voiceUrl, String httpMethod,
                                String headerString, String payload, String httpResponse, String mobile,
                                String otpToken) throws IOException, AuthenticationFailedException {

        if (log.isDebugEnabled()) {
            log.debug("Preparing message for sending out");
        }
        HttpURLConnection httpConnection;
        boolean connection;
        String voiceMessage = VoiceOTPConstants.VOICE_MESSAGE;
        String receivedMobileNumber = URLEncoder.encode(mobile, CHAR_SET_UTF_8);

        String encodedVoiceMessage = voiceMessage.replaceAll("\\s", "+");
        voiceUrl = voiceUrl.replaceAll("\\$ctx.num", receivedMobileNumber)
                .replaceAll("\\$ctx.msg", encodedVoiceMessage + otpToken)
                .replaceAll("\\$ctx.otp", otpToken);
        URL voiceProviderUrl = null;
        try {
            voiceProviderUrl = new URL(voiceUrl);
        } catch (MalformedURLException e) {
            log.error("Error while parsing Voice provider URL: " + voiceUrl, e);
            if (VoiceOTPUtils.useInternalErrorCodes(context)) {
                context.setProperty(VoiceOTPConstants.ERROR_CODE, VoiceOTPConstants.ErrorMessage.MALFORMED_URL.getCode());
            } else {
                context.setProperty(VoiceOTPConstants.ERROR_CODE, "The Voice URL does not conform to URL specification");
            }
            return false;
        }
        String subUrl = voiceProviderUrl.getProtocol();
        if (subUrl.equals(VoiceOTPConstants.HTTPS)) {
            httpConnection = (HttpsURLConnection) voiceProviderUrl.openConnection();
        } else {
            httpConnection = (HttpURLConnection) voiceProviderUrl.openConnection();
        }
        connection = getConnection(httpConnection, context, headerString, payload, httpResponse,
                mobile, voiceMessage, otpToken, httpMethod);
        return connection;
    }

    /**
     * Get the corresponding encoded value based on the provided content-type.
     *
     * @param contentType The content type in the request header.
     * @param value       String value that needed to be encoded.
     * @return The encoded value based on the content-type.
     * @throws IOException
     */
    private String getEncodedValue(String contentType, String value) throws IOException {

        String encodedValue;
        switch (contentType) {
            case XML_CONTENT_TYPE:
                encodedValue = Encode.forXml(value);
                break;
            case JSON_CONTENT_TYPE:
                Gson gson = new Gson();
                encodedValue = gson.toJson(value);
                break;
            default:
                encodedValue = URLEncoder.encode(value, CHAR_SET_UTF_8);
        }
        return encodedValue;
    }

    /**
     * Get a screen value from the user attributes. If you need to show n digits of mobile number or any other user
     * attribute value in the UI.
     *
     * @param userRealm the user Realm
     * @param username  the username
     * @return the screen attribute
     * @throws UserStoreException
     */
    public String getScreenAttribute(AuthenticationContext context, UserRealm userRealm, String username)
            throws UserStoreException {

        String screenUserAttributeParam;
        String screenUserAttributeValue = null;
        String screenValue = null;
        int noOfDigits = 0;

        screenUserAttributeParam = VoiceOTPUtils.getScreenUserAttribute(context);
        if (screenUserAttributeParam != null) {
            screenUserAttributeValue = userRealm.getUserStoreManager()
                    .getUserClaimValue(username, screenUserAttributeParam, null);

            if (StringUtils.isBlank(screenUserAttributeValue)) {
                screenUserAttributeValue = String.valueOf(context.getProperty(REQUESTED_USER_MOBILE));
            }
        }

        if (StringUtils.isNotBlank(screenUserAttributeValue)) {
            if ((VoiceOTPUtils.getNoOfDigits(context)) != null) {
                noOfDigits = Integer.parseInt(VoiceOTPUtils.getNoOfDigits(context));
            }
            screenValue = getMaskedValue(context, screenUserAttributeValue, noOfDigits);
        }
        return screenValue;
    }

    private String getMaskedValue(AuthenticationContext context, String screenUserAttributeValue, int noOfDigits) {

        String screenValue;
        String hiddenScreenValue;
        String maskingRegex = VoiceOTPUtils.getScreenValueRegex(context);

        if (StringUtils.isNotEmpty(maskingRegex)) {
            screenValue = screenUserAttributeValue.replaceAll(maskingRegex, VoiceOTPConstants.SCREEN_VALUE_MASKING_CHARACTER);
            return screenValue;
        }

        int screenAttributeLength = screenUserAttributeValue.length();
        // Ensure noOfDigits is not greater than screenAttributeLength.
        noOfDigits = Math.min(noOfDigits, screenAttributeLength);
        if (screenAttributeLength <= noOfDigits && log.isDebugEnabled()) {
            log.debug("Mobile number length is less than or equal to noOfDigits: " + noOfDigits);
        }
        if (VoiceOTPConstants.BACKWARD.equals(VoiceOTPUtils.getDigitsOrder(context))) {
            screenValue = screenUserAttributeValue.substring(screenAttributeLength - noOfDigits,
                    screenAttributeLength);
            hiddenScreenValue = screenUserAttributeValue.substring(0, screenAttributeLength - noOfDigits);
            for (int i = 0; i < hiddenScreenValue.length(); i++) {
                screenValue = ("*").concat(screenValue);
            }
        } else {
            screenValue = screenUserAttributeValue.substring(0, noOfDigits);
            hiddenScreenValue = screenUserAttributeValue.substring(noOfDigits, screenAttributeLength);
            for (int i = 0; i < hiddenScreenValue.length(); i++) {
                screenValue = screenValue.concat("*");
            }
        }
        return screenValue;
    }

    /**
     * We can reuse this method once the improvements done into the eventing and notification handler in IS.
     */
    protected void triggerNotification(String userName, String tenantDomain, String userStoreDomainName,
                                       String mobileNumber, String otpCode, String serviceProviderName,
                                       long otpExpiryTime) {

        String eventName = TRIGGER_VOICE_NOTIFICATION;

        HashMap<String, Object> properties = new HashMap<>();
        properties.put(IdentityEventConstants.EventProperty.USER_NAME, userName);
        properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, userStoreDomainName);
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, tenantDomain);
        properties.put(IdentityEventConstants.EventProperty.NOTIFICATION_CHANNEL,
                NotificationChannels.VOICE_CHANNEL.getChannelType());
        properties.put(VoiceOTPConstants.ATTRIBUTE_VOICE_SENT_TO, mobileNumber);
        properties.put(VoiceOTPConstants.OTP_TOKEN, otpCode);
        properties.put(VoiceOTPConstants.CORRELATION_ID, getCorrelationId());
        properties.put(VoiceOTPConstants.TEMPLATE_TYPE, VoiceOTPConstants.EVENT_NAME);
        properties.put(IdentityEventConstants.EventProperty.APPLICATION_NAME, serviceProviderName);
        properties.put(IdentityEventConstants.EventProperty.OTP_EXPIRY_TIME, String.valueOf(otpExpiryTime / 60));
        Event identityMgtEvent = new Event(eventName, properties);
        try {
            VoiceOTPServiceDataHolder.getInstance().getIdentityEventService().handleEvent(identityMgtEvent);
        } catch (Exception e) {
            String errorMsg = "Error occurred while calling triggerNotification, detail : " + e.getMessage();
            //We are not throwing any exception from here, because this event notification should not break the main
            // flow.
            log.warn(errorMsg);
            if (log.isDebugEnabled()) {
                log.debug(errorMsg, e);
            }
        }
    }

    /**
     * Get correlation id of current thread.
     *
     * @return correlation-id.
     */
    public static String getCorrelationId() {

        return StringUtils.isBlank(MDC.get(VoiceOTPConstants.CORRELATION_ID_MDC))
                ? UUID.randomUUID().toString() : MDC.get(VoiceOTPConstants.CORRELATION_ID_MDC);
    }

    private String getHttpErrorResponseCode(String errorMsg) {

        String errorCode = errorMsg;
        if (StringUtils.contains(errorCode, ":")) {
            errorCode = errorCode.split(":")[0];
        }
        return StringUtils.trim(errorCode);
    }

    /**
     * Reset Voice OTP Failed Attempts count upon successful completion of the Voice OTP verification.
     *
     * @param context Authentication context.
     * @throws AuthenticationFailedException Exception on authentication failure.
     */
    private void resetVoiceOtpFailedAttempts(AuthenticationContext context) throws AuthenticationFailedException {
        
        /*
        Check whether account locking enabled for Voice OTP to keep backward compatibility.
        Account locking is not done for federated flows.
         */
        if (!VoiceOTPUtils.isLocalUser(context) || !VoiceOTPUtils.isAccountLockingEnabledForVoiceOtp(context)) {
            return;
        }
        AuthenticatedUser authenticatedUser =
                (AuthenticatedUser) context.getProperty(VoiceOTPConstants.AUTHENTICATED_USER);
        Property[] connectorConfigs = VoiceOTPUtils.getAccountLockConnectorConfigs(authenticatedUser.getTenantDomain());

        // Return if account lock handler is not enabled.
        for (Property connectorConfig : connectorConfigs) {
            if ((VoiceOTPConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE.equals(connectorConfig.getName())) &&
                    !Boolean.parseBoolean(connectorConfig.getValue())) {
                return;
            }
        }

        String usernameWithDomain = IdentityUtil.addDomainToName(authenticatedUser.getUserName(),
                authenticatedUser.getUserStoreDomain());
        try {
            UserRealm userRealm = getUserRealm(authenticatedUser);
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();

            // Avoid updating the claims if they are already zero.
            String[] claimsToCheck = {VoiceOTPConstants.VOICE_OTP_FAILED_ATTEMPTS_CLAIM};
            Map<String, String> userClaims = userStoreManager.getUserClaimValues(usernameWithDomain, claimsToCheck,
                    UserCoreConstants.DEFAULT_PROFILE);
            String failedVoiceOtpAttempts = userClaims.get(VoiceOTPConstants.VOICE_OTP_FAILED_ATTEMPTS_CLAIM);

            if (NumberUtils.isNumber(failedVoiceOtpAttempts) && Integer.parseInt(failedVoiceOtpAttempts) > 0) {
                Map<String, String> updatedClaims = new HashMap<>();
                updatedClaims.put(VoiceOTPConstants.VOICE_OTP_FAILED_ATTEMPTS_CLAIM, "0");
                userStoreManager
                        .setUserClaimValues(usernameWithDomain, updatedClaims, UserCoreConstants.DEFAULT_PROFILE);
            }
        } catch (UserStoreException e) {
            log.error("Error while resetting failed Voice OTP attempts", e);
            String errorMessage =
                    String.format("Failed to reset failed attempts count for user : %s.", authenticatedUser);
            throw new AuthenticationFailedException(errorMessage, e);
        }
    }

    /**
     * Execute account lock flow for OTP verification failures.
     *
     * @param context Authentication context.
     * @throws AuthenticationFailedException Exception on authentication failure.
     */
    private void handleVoiceOtpVerificationFail(AuthenticationContext context) throws AuthenticationFailedException {

        AuthenticatedUser authenticatedUser =
                (AuthenticatedUser) context.getProperty(VoiceOTPConstants.AUTHENTICATED_USER);

        /*
        Account locking is not done for federated flows.
        Check whether account locking enabled for Voice OTP to keep backward compatibility.
        No need to continue if the account is already locked.
         */
        if (!VoiceOTPUtils.isLocalUser(context) || !VoiceOTPUtils.isAccountLockingEnabledForVoiceOtp(context) ||
                VoiceOTPUtils.isAccountLocked(authenticatedUser)) {
            return;
        }
        int maxAttempts = 0;
        long unlockTimePropertyValue = 0;
        double unlockTimeRatio = 1;

        Property[] connectorConfigs = VoiceOTPUtils.getAccountLockConnectorConfigs(authenticatedUser.getTenantDomain());
        for (Property connectorConfig : connectorConfigs) {
            switch (connectorConfig.getName()) {
                case VoiceOTPConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE:
                    if (!Boolean.parseBoolean(connectorConfig.getValue())) {
                        return;
                    }
                case VoiceOTPConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE_MAX:
                    if (NumberUtils.isNumber(connectorConfig.getValue())) {
                        maxAttempts = Integer.parseInt(connectorConfig.getValue());
                    }
                    break;
                case VoiceOTPConstants.PROPERTY_ACCOUNT_LOCK_TIME:
                    if (NumberUtils.isNumber(connectorConfig.getValue())) {
                        unlockTimePropertyValue = Integer.parseInt(connectorConfig.getValue());
                    }
                    break;
                case VoiceOTPConstants.PROPERTY_LOGIN_FAIL_TIMEOUT_RATIO:
                    if (NumberUtils.isNumber(connectorConfig.getValue())) {
                        double value = Double.parseDouble(connectorConfig.getValue());
                        if (value > 0) {
                            unlockTimeRatio = value;
                        }
                    }
                    break;
            }
        }
        Map<String, String> claimValues = getUserClaimValues(authenticatedUser);
        if (claimValues == null) {
            claimValues = new HashMap<>();
        }
        int currentAttempts = 0;
        if (NumberUtils.isNumber(claimValues.get(VoiceOTPConstants.VOICE_OTP_FAILED_ATTEMPTS_CLAIM))) {
            currentAttempts = Integer.parseInt(claimValues.get(VoiceOTPConstants.VOICE_OTP_FAILED_ATTEMPTS_CLAIM));
        }
        int failedLoginLockoutCountValue = 0;
        if (NumberUtils.isNumber(claimValues.get(VoiceOTPConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM))) {
            failedLoginLockoutCountValue =
                    Integer.parseInt(claimValues.get(VoiceOTPConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM));
        }

        Map<String, String> updatedClaims = new HashMap<>();
        if ((currentAttempts + 1) >= maxAttempts) {
            // Calculate the incremental unlock-time-interval in milli seconds.
            unlockTimePropertyValue = (long) (unlockTimePropertyValue * 1000 * 60 * Math.pow(unlockTimeRatio,
                    failedLoginLockoutCountValue));
            // Calculate unlock-time by adding current-time and unlock-time-interval in milli seconds.
            long unlockTime = System.currentTimeMillis() + unlockTimePropertyValue;
            updatedClaims.put(VoiceOTPConstants.ACCOUNT_LOCKED_CLAIM, Boolean.TRUE.toString());
            updatedClaims.put(VoiceOTPConstants.VOICE_OTP_FAILED_ATTEMPTS_CLAIM, "0");
            updatedClaims.put(VoiceOTPConstants.ACCOUNT_UNLOCK_TIME_CLAIM, String.valueOf(unlockTime));
            updatedClaims.put(VoiceOTPConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM,
                    String.valueOf(failedLoginLockoutCountValue + 1));
            updatedClaims.put(VoiceOTPConstants.ACCOUNT_LOCKED_REASON_CLAIM_URI,
                    VoiceOTPConstants.MAX_VOICE_OTP_ATTEMPTS_EXCEEDED);
            IdentityUtil.threadLocalProperties.get().put(VoiceOTPConstants.ADMIN_INITIATED, false);
            setUserClaimValues(authenticatedUser, updatedClaims);
            String errorMessage = String.format("User account: %s is locked.", authenticatedUser.getUserName());
            throw new AuthenticationFailedException(errorMessage);
        } else {
            updatedClaims.put(VoiceOTPConstants.VOICE_OTP_FAILED_ATTEMPTS_CLAIM, String.valueOf(currentAttempts + 1));
            setUserClaimValues(authenticatedUser, updatedClaims);
        }
    }

    private Map<String, String> getUserClaimValues(AuthenticatedUser authenticatedUser)
            throws AuthenticationFailedException {

        Map<String, String> claimValues;
        try {
            UserRealm userRealm = getUserRealm(authenticatedUser);
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            claimValues = userStoreManager.getUserClaimValues(IdentityUtil.addDomainToName(
                            authenticatedUser.getUserName(), authenticatedUser.getUserStoreDomain()), new String[]{
                            VoiceOTPConstants.VOICE_OTP_FAILED_ATTEMPTS_CLAIM,
                            VoiceOTPConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM},
                    UserCoreConstants.DEFAULT_PROFILE);
        } catch (UserStoreException e) {
            log.error("Error while reading user claims", e);
            String errorMessage = String.format("Failed to read user claims for user : %s.", authenticatedUser);
            throw new AuthenticationFailedException(errorMessage, e);
        }
        return claimValues;
    }

    private void setUserClaimValues(AuthenticatedUser authenticatedUser, Map<String, String> updatedClaims)
            throws AuthenticationFailedException {

        try {
            UserRealm userRealm = getUserRealm(authenticatedUser);
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            userStoreManager.setUserClaimValues(IdentityUtil.addDomainToName(authenticatedUser.getUserName(),
                    authenticatedUser.getUserStoreDomain()), updatedClaims, UserCoreConstants.DEFAULT_PROFILE);
        } catch (UserStoreException e) {
            log.error("Error while updating user claims", e);
            String errorMessage = String.format("Failed to update user claims for user : %s.", authenticatedUser);
            throw new AuthenticationFailedException(errorMessage, e);
        }
    }

    /**
     * Get user account unlock time in milli seconds. If no value configured for unlock time user claim, return 0.
     *
     * @param authenticatedUser The authenticated user.
     * @return User account unlock time in milli seconds. If no value is configured return 0.
     * @throws AuthenticationFailedException If an error occurred while getting the user unlock time.
     */
    private long getUnlockTimeInMilliSeconds(AuthenticatedUser authenticatedUser) throws AuthenticationFailedException {

        String username = authenticatedUser.toFullQualifiedUsername();
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        try {
            UserRealm userRealm = getUserRealm(username);
            if (userRealm == null) {
                throw new AuthenticationFailedException("UserRealm is null for user : " + username);
            }
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            if (userStoreManager == null) {
                if (log.isDebugEnabled()) {
                    log.debug("userStoreManager is null for user: " + username);
                }
                throw new AuthenticationFailedException("userStoreManager is null for user: " + username);
            }
            Map<String, String> claimValues = userStoreManager
                    .getUserClaimValues(tenantAwareUsername, new String[]{VoiceOTPConstants.ACCOUNT_UNLOCK_TIME_CLAIM},
                            null);
            if (claimValues.get(VoiceOTPConstants.ACCOUNT_UNLOCK_TIME_CLAIM) == null) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("No value configured for claim: %s, of user: %s",
                            VoiceOTPConstants.ACCOUNT_UNLOCK_TIME_CLAIM, username));
                }
                return 0;
            }
            return Long.parseLong(claimValues.get(VoiceOTPConstants.ACCOUNT_UNLOCK_TIME_CLAIM));
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Cannot find the user claim for unlock time for user : " +
                    username, e);
        }
    }

    /**
     * Trigger event after generating Voice OTP.
     *
     * @param request HttpServletRequest.
     * @param context Authentication context.
     * @throws AuthenticationFailedException Exception on authentication failure.
     */
    private void publishPostVoiceOTPGeneratedEvent(HttpServletRequest request, AuthenticationContext context)
            throws AuthenticationFailedException {

        Map<String, Object> eventProperties = new HashMap<>();
        eventProperties.put(IdentityEventConstants.EventProperty.CORRELATION_ID, context.getCallerSessionKey());
        AuthenticatedUser authenticatedUser = (AuthenticatedUser) context.getProperty(VoiceOTPConstants
                .AUTHENTICATED_USER);
        eventProperties.put(IdentityEventConstants.EventProperty.USER_NAME, authenticatedUser.getUserName());
        eventProperties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, context.getTenantDomain());
        eventProperties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, authenticatedUser
                .getUserStoreDomain());
        eventProperties.put(IdentityEventConstants.EventProperty.APPLICATION_NAME, context.getServiceProviderName());
        eventProperties.put(IdentityEventConstants.EventProperty.USER_AGENT, request.getHeader(
                VoiceOTPConstants.USER_AGENT));
        if (request.getParameter(VoiceOTPConstants.RESEND) != null) {
            if (log.isDebugEnabled()) {
                log.debug("Setting true resend-code property in event since http request has resendCode parameter.");
            }
            eventProperties.put(IdentityEventConstants.EventProperty.RESEND_CODE,
                    request.getParameter(VoiceOTPConstants.RESEND));
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Setting false resend-code property in event since http request has not resendCode parameter.");
            }
            eventProperties.put(IdentityEventConstants.EventProperty.RESEND_CODE, false);
        }

        eventProperties.put(IdentityEventConstants.EventProperty.GENERATED_OTP, context.getProperty(
                VoiceOTPConstants.OTP_TOKEN));

        Object otpGeneratedTimeProperty = context.getProperty(VoiceOTPConstants.SENT_OTP_TOKEN_TIME);
        if (otpGeneratedTimeProperty != null) {
            long otpGeneratedTime = (long) otpGeneratedTimeProperty;
            eventProperties.put(IdentityEventConstants.EventProperty.OTP_GENERATED_TIME, otpGeneratedTime);

            String otpValidityPeriod = VoiceOTPUtils.getTokenExpiryTime(context);
            long expiryTime = otpGeneratedTime + (StringUtils.isEmpty(otpValidityPeriod) ?
                    VoiceOTPConstants.DEFAULT_VALIDITY_PERIOD : Long.parseLong(otpValidityPeriod));
            eventProperties.put(IdentityEventConstants.EventProperty.OTP_EXPIRY_TIME, expiryTime);
        }

        eventProperties.put(IdentityEventConstants.EventProperty.CLIENT_IP, IdentityUtil.getClientIpAddress(request));
        Event postOtpGenEvent = new Event(IdentityEventConstants.Event.POST_GENERATE_VOICE_OTP, eventProperties);
        try {
            VoiceOTPServiceDataHolder.getInstance().getIdentityEventService().handleEvent(postOtpGenEvent);
        } catch (IdentityEventException e) {
            String errorMsg = "An error occurred while triggering post event in Voice OTP generation flow. " + e.getMessage();
            throw new AuthenticationFailedException(errorMsg, e);
        }
    }

    /**
     * Trigger event after validating Voice OTP.
     *
     * @param request HttpServletRequest.
     * @param context Authentication context.
     * @throws AuthenticationFailedException Exception on authentication failure.
     */
    private void publishPostVoiceOTPValidatedEvent(HttpServletRequest request,
                                                   AuthenticationContext context) throws AuthenticationFailedException {

        Map<String, Object> eventProperties = new HashMap<>();
        AuthenticatedUser authenticatedUser = (AuthenticatedUser) context.getProperty(VoiceOTPConstants
                .AUTHENTICATED_USER);
        eventProperties.put(IdentityEventConstants.EventProperty.CORRELATION_ID, context.getCallerSessionKey());
        eventProperties.put(IdentityEventConstants.EventProperty.USER_NAME, authenticatedUser.getUserName());
        eventProperties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, context.getTenantDomain());
        eventProperties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, authenticatedUser
                .getUserStoreDomain());
        eventProperties.put(IdentityEventConstants.EventProperty.APPLICATION_NAME, context.getServiceProviderName());
        eventProperties.put(IdentityEventConstants.EventProperty.USER_AGENT, request.getHeader(
                VoiceOTPConstants.USER_AGENT));

        eventProperties.put(IdentityEventConstants.EventProperty.CLIENT_IP, IdentityUtil.getClientIpAddress(request));
        eventProperties.put(IdentityEventConstants.EventProperty.GENERATED_OTP, context.getProperty(
                VoiceOTPConstants.OTP_TOKEN));
        eventProperties.put(IdentityEventConstants.EventProperty.USER_INPUT_OTP, request.getParameter(
                VoiceOTPConstants.CODE));
        eventProperties.put(IdentityEventConstants.EventProperty.OTP_USED_TIME, System.currentTimeMillis());

        long otpGeneratedTime = (long) context.getProperty(VoiceOTPConstants.SENT_OTP_TOKEN_TIME);
        eventProperties.put(IdentityEventConstants.EventProperty.OTP_GENERATED_TIME,
                otpGeneratedTime);

        String otpValidityPeriod = VoiceOTPUtils.getTokenExpiryTime(context);
        long expiryTime = otpGeneratedTime + (StringUtils.isEmpty(otpValidityPeriod) ?
                VoiceOTPConstants.DEFAULT_VALIDITY_PERIOD : Long.parseLong(otpValidityPeriod));
        eventProperties.put(IdentityEventConstants.EventProperty.OTP_EXPIRY_TIME, expiryTime);

        String status;
        if (VoiceOTPConstants.TOKEN_EXPIRED_VALUE.equals(context.getProperty(VoiceOTPConstants.TOKEN_EXPIRED))) {
            status = VoiceOTPConstants.STATUS_OTP_EXPIRED;
        } else if (context.getProperty(VoiceOTPConstants.CODE_MISMATCH) != null && (boolean) context.getProperty(
                VoiceOTPConstants.CODE_MISMATCH)) {
            status = VoiceOTPConstants.STATUS_CODE_MISMATCH;
        } else {
            status = VoiceOTPConstants.STATUS_SUCCESS;
        }

        eventProperties.put(IdentityEventConstants.EventProperty.OTP_STATUS, status);
        Event postOtpValidateEvent = new Event(IdentityEventConstants.Event.POST_VALIDATE_VOICE_OTP, eventProperties);

        try {
            VoiceOTPServiceDataHolder.getInstance().getIdentityEventService().handleEvent(postOtpValidateEvent);
        } catch (IdentityEventException e) {
            String errorMsg = "An error occurred while triggering post event in Voice OTP validation flow. " + e.getMessage();
            throw new AuthenticationFailedException(errorMsg, e);
        }
    }

    /*
     * This method returns the boolean value of the mobile number update failed context property.
     *
     * @param context
     * @return The status of mobile number update failed parameter
     */
    private boolean isMobileNumberUpdateFailed(AuthenticationContext context) {

        return Boolean.parseBoolean(String.valueOf(context.getProperty(VoiceOTPConstants.MOBILE_NUMBER_UPDATE_FAILURE)));
    }

    /**
     * This method returns the boolean value of the code mismatch context property.
     *
     * @param context
     * @return The value of the code mismatch parameter
     */
    private boolean isCodeMismatch(AuthenticationContext context) {

        return Boolean.parseBoolean(String.valueOf(context.getProperty(VoiceOTPConstants.CODE_MISMATCH)));
    }
}

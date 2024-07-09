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
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
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
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
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
import static org.wso2.carbon.identity.authenticator.voiceotp.VoiceOTPConstants.REQUESTED_USER_MOBILE;
import static org.wso2.carbon.identity.authenticator.voiceotp.VoiceOTPConstants.XML_CONTENT_TYPE;

import static java.util.Base64.getEncoder;

/**
 * Authenticator of Voice OTP.
 */
public class VoiceOTPAuthenticator extends AbstractApplicationAuthenticator
        implements FederatedApplicationAuthenticator {

    private static final Log LOG = LogFactory.getLog(VoiceOTPAuthenticator.class);

    /**
     * Check whether the authentication or logout request can be handled by the authenticator.
     *
     * @param request The HttpServletRequest.
     * @return Whether the authenticator can handle the inbound request.
     */
    @Override
    public boolean canHandle(HttpServletRequest request) {

        LOG.debug("Inside VoiceOTPAuthenticator canHandle method and check the existence of mobile number or " +
                    "otp code.");

        return ((StringUtils.isNotEmpty(request.getParameter(VoiceOTPConstants.RESEND))
                && StringUtils.isEmpty(request.getParameter(VoiceOTPConstants.CODE)))
                || StringUtils.isNotEmpty(request.getParameter(VoiceOTPConstants.CODE))
                || StringUtils.isNotEmpty(request.getParameter(VoiceOTPConstants.MOBILE_NUMBER)));
    }

    /**
     * Process the authentication request based on the request type.
     *
     * @param request The HttpServletRequest.
     * @param response The HttpServletResponse.
     * @param context The AuthenticationContext.
     * @return AuthenticatorFlowStatus type.
     */
    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request,
                                           HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        // If the logout request comes, then no need to go through and complete the flow.
        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        } else if (StringUtils.isNotEmpty(request.getParameter(VoiceOTPConstants.MOBILE_NUMBER))) {
            // if the request comes with MOBILE_NUMBER, it will go through this flow.
            initiateAuthenticationRequest(request, response, context);
            return AuthenticatorFlowStatus.INCOMPLETE;
        } else if (StringUtils.isEmpty(request.getParameter(VoiceOTPConstants.CODE))) {
            // if the request doesn't have code, it will go through this flow.
            initiateAuthenticationRequest(request, response, context);
            if (context.getProperty(VoiceOTPConstants.AUTHENTICATION)
                    .equals(VoiceOTPConstants.AUTHENTICATOR_NAME)) {
                // if the request comes with authentication is VoiceOTP, it will go through this flow.
                return AuthenticatorFlowStatus.INCOMPLETE;
            } else {
                // if the request comes with authentication as any other authenticator name, complete the flow.
                return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
            }
        } else {
            AuthenticatorFlowStatus authenticatorFlowStatus = super.process(request, response, context);
            return authenticatorFlowStatus;
        }
    }

    /**
     * Protected helper method to initiate the authentication request.
     * This method performs several steps to initiate the authentication flow based on VoiceOTP configuration
     * and user context:
     *
     * @param request  The HTTP servlet request.
     * @param response The HTTP servlet response.
     * @param context  The authentication context.
     * @throws AuthenticationFailedException  If authentication fails due to missing user, VoiceOTP errors,
     *                                       or user store errors.
     * @see VoiceOTPConstants
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
            if (!VoiceOTPConstants.SUPER_TENANT.equals(tenantDomain)) {
                IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, getName(), tenantDomain);
            }
            FederatedAuthenticatorUtil.setUsernameFromFirstStep(context);
            username = String.valueOf(context.getProperty(VoiceOTPConstants.USER_NAME));
            authenticatedUser = (AuthenticatedUser) context.getProperty(VoiceOTPConstants.AUTHENTICATED_USER);
            // Find the authenticated user.
            if (authenticatedUser == null) {
                LOG.error("Authentication failed: Could not find the authenticated user.");
                throw new AuthenticationFailedException
                        ("Authentication failed: Cannot proceed further without identifying the user.");
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
                LOG.debug("Voice OTP is mandatory. Hence processing in mandatory path.");
                processVoiceOTPMandatoryCase(context, request, response, queryParams, username, isUserExists);
            // Checks whether local user exists and the voice otp is not disabled for the user.
            } else if (isUserExists && !VoiceOTPUtils.isVoiceOTPDisableForLocalUser(username, context)) {
                // Trigger retry flow when it is not request for resending OTP, it is not mobile number update failure
                // or the user is a local user and the user account is locked.
                if ((context.isRetrying() && !Boolean.parseBoolean(request.getParameter(VoiceOTPConstants.RESEND))
                        && !isMobileNumberUpdateFailed(context)) || (VoiceOTPUtils.isLocalUser(context) &&
                        VoiceOTPUtils.isAccountLocked(authenticatedUser))) {

                    LOG.debug("Triggering Voice OTP retry flow.");

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
            throw new AuthenticationFailedException("Failed to get the parameters from authentication xml file.", e);
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Failed to get the user from User Store.", e);
        }
    }

    /**
     * Get MultiOptionURI query parameter from the request.
     *
     * @param request Http servlet request.
     * @return MultiOptionURI query parameter.
     */
    private String getMultiOptionURIQueryParam(HttpServletRequest request) {

        if (request != null && StringUtils.isNotEmpty(request.getParameter(VoiceOTPConstants.MULTI_OPTION_URI))) {
            return "&" + VoiceOTPConstants.MULTI_OPTION_URI + "="
                        + Encode.forUriComponent(request.getParameter(VoiceOTPConstants.MULTI_OPTION_URI));
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
     * @return the mobile number.
     * @throws AuthenticationFailedException Exception.
     * @throws VoiceOTPException Exception.
     */
    private String getMobileNumber(HttpServletRequest request, HttpServletResponse response,
                                   AuthenticationContext context, String username,
                                   String queryParams) throws AuthenticationFailedException, VoiceOTPException {

        String mobileNumber = VoiceOTPUtils.getMobileNumberForUsername(username);
        if (StringUtils.isEmpty(mobileNumber)) {
            String userMobileEntered = request.getParameter(VoiceOTPConstants.MOBILE_NUMBER);
            if (StringUtils.isBlank(userMobileEntered) &&
                    !isMobileNumberUpdateFailed(context) && isCodeMismatch(context)) {
                mobileNumber = String.valueOf(context.getProperty(VoiceOTPConstants.REQUESTED_USER_MOBILE));
            } else if (StringUtils.isBlank(userMobileEntered)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("User does not have a registered mobile number: " + username);
                }
                redirectToMobileNoReqPage(response, context, queryParams);
            } else {
                context.setProperty(VoiceOTPConstants.REQUESTED_USER_MOBILE, userMobileEntered);
                mobileNumber = userMobileEntered;
            }
        }
        return mobileNumber;
    }

    /**
     * Get the loginPage from authentication.xml file or use the login page from constant file.
     *
     * @param context The AuthenticationContext.
     * @return The loginPage.
     */
    private String getLoginPage(AuthenticationContext context) {

        String loginPage = VoiceOTPUtils.getLoginPageFromXMLFile(context);
        if (StringUtils.isEmpty(loginPage)) {
            loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                    .replace(VoiceOTPConstants.LOGIN_PAGE, VoiceOTPConstants.VOICE_LOGIN_PAGE);

            LOG.debug("Login Page is not defined in the configurations. " +
                    "Default authentication endpoint context is used.");
        }
        return loginPage;
    }

    /**
     * Get the errorPage from authentication.xml file or use the error page from constant file.
     *
     * @param context The AuthenticationContext.
     * @return The errorPage.
     * @throws AuthenticationFailedException Exception.
     */
    private String getErrorPage(AuthenticationContext context) throws AuthenticationFailedException {

        String errorPage = VoiceOTPUtils.getErrorPageFromXMLFile(context);
        if (StringUtils.isEmpty(errorPage)) {
            errorPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                    .replace(VoiceOTPConstants.LOGIN_PAGE, VoiceOTPConstants.ERROR_PAGE);

            LOG.debug("Error page is not defined in the configurations. " +
                    "Default authentication endpoint context is used.");
        }
        return errorPage;
    }

    /**
     * To get the redirection URL.
     *
     * @param baseURI     The base path.
     * @param queryParams The queryParams.
     * @return URL.
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
     * @param response    The HttpServletResponse.
     * @param queryParams The queryParams.
     * @throws AuthenticationFailedException Exception.
     */
    private void redirectToErrorPage(HttpServletResponse response, AuthenticationContext context, String queryParams,
                                     String retryParam)
            throws AuthenticationFailedException {

        // That Enable the Voice OTP in user's Profile. Cannot proceed further without Voice OTP authentication.
        try {
            String errorPage = getErrorPage(context);
            String url = getURL(errorPage, queryParams);
            response.sendRedirect(url + retryParam);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Exception occurred while redirecting to errorPage.", e);
        }
    }

    /**
     * In VoiceOTP optional case proceed with first step only.It can be basic or federated.
     *
     * @param authenticatedUser The name of authenticatedUser.
     * @param context           The AuthenticationContext.
     */
    private void processFirstStepOnly(AuthenticatedUser authenticatedUser, AuthenticationContext context) {

        LOG.debug("Processing First step only. Skipping VoiceOTP.");

        // The authentication flow happens with basic authentication.
        StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(context.getCurrentStep() - 1);
        if (stepConfig.getAuthenticatedAutenticator().getApplicationAuthenticator() instanceof
                LocalApplicationAuthenticator) {

            LOG.debug("Found local authenticator in previous step. Hence setting a local user.");

            FederatedAuthenticatorUtil.updateLocalAuthenticatedUserInStepConfig(context, authenticatedUser);
            context.setProperty(VoiceOTPConstants.AUTHENTICATION, VoiceOTPConstants.BASIC);
        } else {

            LOG.debug("Found federated authenticator in previous step. Hence setting a federated user.");

            FederatedAuthenticatorUtil.updateAuthenticatedUserInStepConfig(context, authenticatedUser);
            context.setProperty(VoiceOTPConstants.AUTHENTICATION, VoiceOTPConstants.FEDERETOR);
        }
    }

    /**
     * Update mobile number when user forgets to update the mobile number in user's profile.
     *
     * @param context      The AuthenticationContext.
     * @param request      The HttpServletRequest.
     * @param username     The Username.
     * @param tenantDomain The TenantDomain.
     * @throws VoiceOTPException Exception.
     * @throws UserStoreException Exception.
     */
    private void updateMobileNumberForUsername(AuthenticationContext context, HttpServletRequest request,
                                               String username, String tenantDomain)
            throws VoiceOTPException, UserStoreException {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Updating mobile number for user : " + username);
        }
        Map<String, String> attributes = new HashMap<>();
        attributes.put(VoiceOTPConstants.MOBILE_CLAIM,
                String.valueOf(context.getProperty(VoiceOTPConstants.REQUESTED_USER_MOBILE)));
        VoiceOTPUtils.updateUserAttribute(MultitenantUtils.getTenantAwareUsername(username), attributes,
                tenantDomain);
    }

    /**
     * Check with VoiceOTP mandatory case with VoiceOTP flow.
     *
     * @param context      The AuthenticationContext.
     * @param request      The HttpServletRequest.
     * @param response     The HttpServletResponse.
     * @param queryParams  The queryParams.
     * @param username     The Username.
     * @param isUserExists Check whether user exist or not.
     * @throws AuthenticationFailedException Exception on authentication failure.
     * @throws VoiceOTPException Exception.
     */
    private void processVoiceOTPMandatoryCase(AuthenticationContext context, HttpServletRequest request,
                                              HttpServletResponse response, String queryParams, String username,
                                              boolean isUserExists)
            throws AuthenticationFailedException, VoiceOTPException {

        // The authentication flow happens with voice otp authentication.
        String tenantDomain = context.getTenantDomain();
        String errorPage = getErrorPage(context);
        if (context.isRetrying() && !Boolean.parseBoolean(request.getParameter(VoiceOTPConstants.RESEND))
                && !isMobileNumberUpdateFailed(context)) {

            LOG.debug("Trigger retry flow when it is not " +
                        "request for resending OTP or it is not mobile number update failure.");

            checkStatusCode(response, context, queryParams, errorPage);
        } else {
            processVoiceOTPFlow(context, request, response, isUserExists, username, queryParams, tenantDomain,
                    errorPage);
        }
    }

    /**
     * This method will retrieve the mobile number of the federated user and proceed.
     *
     * @param context The AuthenticationContext.
     * @param response The HttpServletResponse.
     * @param username Username.
     * @param queryParams Request query params.
     * @param sendOtpToFederatedMobile Whether it needs to send the otp for federated user mobile number.
     * @throws AuthenticationFailedException Exception on authentication failure.
     */
    private void proceedOTPWithFederatedMobileNumber(AuthenticationContext context, HttpServletResponse response,
                                                     String username, String queryParams,
                                                     boolean sendOtpToFederatedMobile)
            throws AuthenticationFailedException, VoiceOTPException {

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
                    if (key != null && key.equals(federatedMobileAttributeKey)) {
                        mobile = String.valueOf(value);
                        proceedWithOTP(response, context, getErrorPage(context), mobile, queryParams, username);
                        break;
                    }
                }
                if (StringUtils.isEmpty(mobile)) {

                    LOG.debug("There is no mobile claim to send otp.");

                    throw new AuthenticationFailedException("There is no mobile claim to send otp.");
                }
            } else {
                redirectToErrorPage(response, context, queryParams, VoiceOTPConstants.SEND_OTP_DIRECTLY_DISABLE);
            }
        } catch (AuthenticationFailedException e) {
            throw new AuthenticationFailedException("Failed to process VoiceOTP flow.", e);
        }
    }

    /**
     * This method will return the configured federatedMobileAttributeKey.
     *
     * @param context AuthenticationContext.
     * @param authenticatorName Authenticator name.
     * @return Configured federated Mobile attribute key.
     */
    private String getFederatedMobileAttributeKey(AuthenticationContext context, String authenticatorName) {

        String federatedVoiceAttributeKey = null;
        Map<String, String> parametersMap;
        String tenantDomain = context.getTenantDomain();
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        if (propertiesFromLocal != null || VoiceOTPConstants.SUPER_TENANT.equals(tenantDomain)) {
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
     * @param context      The AuthenticationContext.
     * @param request      The HttpServletRequest.
     * @param response     The HttpServletResponse.
     * @param isUserExists Check whether user exist or not.
     * @param username     The UserName.
     * @param queryParams  The queryParams.
     * @param tenantDomain The TenantDomain.
     * @param errorPage    The errorPage.
     * @throws AuthenticationFailedException Exception on authentication failure.
     * @throws VoiceOTPException Exception.
     */
    private void processVoiceOTPFlow(AuthenticationContext context, HttpServletRequest request,
                                     HttpServletResponse response, boolean isUserExists, String username,
                                     String queryParams, String tenantDomain, String errorPage)
            throws AuthenticationFailedException, VoiceOTPException {

        String mobileNumber = null;
        if (isUserExists) {
            boolean isVoiceOTPDisabledByUser = VoiceOTPUtils.isVoiceOTPDisableForLocalUser(username, context);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Has user enabled Voice OTP : " + isVoiceOTPDisabledByUser);
            }
            if (isVoiceOTPDisabledByUser) {
                // That Enable the Voice OTP in user's Profile. Cannot proceed further without Voice OTP authentication.
                redirectToErrorPage(response, context, queryParams, VoiceOTPConstants.ERROR_VOICEOTP_DISABLE);
            } else {
                mobileNumber = getMobileNumber(request, response, context, username, queryParams);
            }
        } else if (VoiceOTPUtils.isSendOTPDirectlyToMobile(context)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("User :" + username + " doesn't exist.");
            }
            if (request.getParameter(VoiceOTPConstants.MOBILE_NUMBER) == null) {

                LOG.debug("Couldn't find the mobile number in request. Hence redirecting to mobile number input " +
                            "page.");

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
                    throw new AuthenticationFailedException("Authentication failed!. An IOException occurred.", e);
                }
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Mobile number found in request : "
                            + request.getParameter(VoiceOTPConstants.MOBILE_NUMBER));
                }
                mobileNumber = request.getParameter(VoiceOTPConstants.MOBILE_NUMBER);
            }
        } else if (VoiceOTPUtils.sendOtpToFederatedMobile(context)) {

            LOG.debug("Voice OTP is mandatory. But user is not there in the user store. " +
                        "Hence send the otp to the federated mobile claim.");

            proceedOTPWithFederatedMobileNumber(context, response, username, queryParams,
                    VoiceOTPUtils.sendOtpToFederatedMobile(context));
        } else {

            LOG.debug("Voice OTP is mandatory. But couldn't find a mobile number.");

            redirectToErrorPage(response, context, queryParams, VoiceOTPConstants.SEND_OTP_DIRECTLY_DISABLE);
        }
        if (StringUtils.isNotEmpty(mobileNumber)) {
            proceedWithOTP(response, context, errorPage, mobileNumber, queryParams, username);
        }
    }

    /**
     * Proceed with One Time Password.
     *
     * @param response     The HttpServletResponse.
     * @param context      The AuthenticationContext.
     * @param errorPage    The errorPage.
     * @param mobileNumber The mobile number.
     * @param queryParams  The queryParams.
     * @param username     The Username.
     * @throws AuthenticationFailedException Exception on authentication failure.
     */
    private void proceedWithOTP(HttpServletResponse response, AuthenticationContext context, String errorPage,
                                String mobileNumber, String queryParams, String username)
            throws AuthenticationFailedException, VoiceOTPException {

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
            OneTimePasswordUtils token = new OneTimePasswordUtils();
            String secret = OneTimePasswordUtils.getRandomNumber(VoiceOTPConstants.SECRET_KEY_LENGTH);
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

            LOG.debug("Generated OTP successfully and set to the context.");

            // Get the values of the voice provider related api parameters.
            String voiceUrl = authenticatorProperties.get(VoiceOTPConstants.VOICE_URL);
            String httpMethod = authenticatorProperties.get(VoiceOTPConstants.HTTP_METHOD);
            String headerString = authenticatorProperties.get(VoiceOTPConstants.HEADERS);
            String payload = authenticatorProperties.get(VoiceOTPConstants.PAYLOAD);
            String httpResponse = authenticatorProperties.get(VoiceOTPConstants.HTTP_RESPONSE);

            if (StringUtils.isEmpty(voiceUrl)) {
                throw new VoiceOTPException("Authenticator Voice URL cannot be empty.");
            }
            boolean connectionResult = sendRESTCall(context, voiceUrl, httpMethod, headerString, payload,
                    httpResponse, mobileNumber, otpToken);

            if (!connectionResult) {
                String retryParam;
                if (context.getProperty(VoiceOTPConstants.ERROR_CODE) != null) {
                    String errorCode = context.getProperty(VoiceOTPConstants.ERROR_CODE).toString();
                    // If UseInternalErrorCodes is configured as true, then http response error codes will be mapped
                    // to local error codes and passed as query param value for authfailure msg.
                    if (VoiceOTPUtils.isUseInternalErrorCodes(context)) {
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
            throw new AuthenticationFailedException("Error while sending the HTTP request.", e);
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Failed to get the user from user store.", e);
        }
    }

    /**
     * Check the status codes when the retry enabled.
     *
     * @param response    The HttpServletResponse.
     * @param context     The AuthenticationContext.
     * @param queryParams The queryParams.
     * @param errorPage   The errorPage.
     * @throws AuthenticationFailedException Exception on authentication failure.
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
                boolean isResendCodeEnabled = VoiceOTPUtils.isEnableResendCode(context);
                if (StringUtils.isNotEmpty((String) context.getProperty(VoiceOTPConstants.TOKEN_EXPIRED))) {
                    response.sendRedirect(url + VoiceOTPConstants.RESEND_CODE
                            + isResendCodeEnabled + VoiceOTPConstants.ERROR_MESSAGE +
                            VoiceOTPConstants.TOKEN_EXPIRED_VALUE);
                } else {
                    response.sendRedirect(url + VoiceOTPConstants.RESEND_CODE
                            + isResendCodeEnabled + VoiceOTPConstants.RETRY_PARAMS);
                }
            } else {
                url = getURL(errorPage, queryParams);
                boolean isResendCodeEnabled = VoiceOTPUtils.isEnableResendCode(context);
                if (Boolean.parseBoolean(String.valueOf(context.getProperty(VoiceOTPConstants.CODE_MISMATCH)))) {
                    response.sendRedirect(url + VoiceOTPConstants.RESEND_CODE
                            + isResendCodeEnabled + VoiceOTPConstants.ERROR_MESSAGE
                            + VoiceOTPConstants.ERROR_CODE_MISMATCH);
                } else if (StringUtils.isNotEmpty((String) context.getProperty(VoiceOTPConstants.TOKEN_EXPIRED))) {
                    response.sendRedirect(url + VoiceOTPConstants.RESEND_CODE
                            + isResendCodeEnabled +
                            VoiceOTPConstants.ERROR_MESSAGE + VoiceOTPConstants.TOKEN_EXPIRED_VALUE);
                } else {
                    response.sendRedirect(url + VoiceOTPConstants.RESEND_CODE
                            + isResendCodeEnabled + VoiceOTPConstants.RETRY_PARAMS);
                }
            }
        } catch (IOException e) {
            throw new AuthenticationFailedException("Authentication Failed: An IOException was caught. ", e);
        }
    }

    /**
     * Get the screen value for configured screen attribute.
     *
     * @param context The AuthenticationContext.
     * @return ScreenValue.
     * @throws AuthenticationFailedException Exception on authentication failure.
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
     * @param response    The HttpServletResponse.
     * @param context     The AuthenticationContext.
     * @param queryParams The queryParams.
     * @throws AuthenticationFailedException Exception on authentication failure.
     */
    private void redirectToMobileNoReqPage(HttpServletResponse response, AuthenticationContext context,
                                           String queryParams) throws AuthenticationFailedException {

        boolean isEnableMobileNoUpdate = VoiceOTPUtils.isEnableMobileNoUpdate(context);
        if (isEnableMobileNoUpdate) {
            String loginPage = VoiceOTPUtils.getMobileNumberRequestPage(context);
            try {
                String url = getURL(loginPage, queryParams);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Redirecting to mobile number request page : " + url);
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
                throw new AuthenticationFailedException("Authentication failed!. An IOException was caught.", e);
            }
        } else {
            throw new AuthenticationFailedException("Authentication failed!. Update mobile no in your profile.");
        }
    }

    /**
     * Process the response of the VoiceOTP end-point.
     *
     * @param request  The HttpServletRequest.
     * @param response The HttpServletResponse.
     * @param context  The AuthenticationContext.
     * @throws AuthenticationFailedException Exception on authentication failure.
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        AuthenticatedUser authenticatedUser = getAuthenticatedUser(context);
        boolean isLocalUser = VoiceOTPUtils.isLocalUser(context);

        if (authenticatedUser != null && isLocalUser && VoiceOTPUtils.isAccountLocked(authenticatedUser)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Authentication failed since authenticated user: %s,  account is locked.",
                        authenticatedUser));
            }
            context.setProperty(VoiceOTPConstants.ACCOUNT_LOCKED, true);
            throw new AuthenticationFailedException("User account is locked.");
        }

        String userToken = request.getParameter(VoiceOTPConstants.CODE);
        String contextToken = (String) context.getProperty(VoiceOTPConstants.OTP_TOKEN);
        if (StringUtils.isEmpty(request.getParameter(VoiceOTPConstants.CODE))) {
            throw new InvalidCredentialsException("Code cannot not be null.");
        }
        if (Boolean.parseBoolean(request.getParameter(VoiceOTPConstants.RESEND))) {

            LOG.debug("Retrying to resend the OTP.");

            throw new InvalidCredentialsException("Retrying to resend the OTP.");
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

            LOG.debug("Given otp code is a mismatch.");

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
                        throw new AuthenticationFailedException("Failed accessing " +
                                "the userstore for user: " + username, e.getCause());
                    } catch (UserStoreClientException e) {
                        context.setProperty(VoiceOTPConstants.MOBILE_NUMBER_UPDATE_FAILURE, "true");
                        throw new AuthenticationFailedException("Mobile claim update failed for user: " + username, e);
                    } catch (UserStoreException e) {
                        Throwable ex = e.getCause();
                        if (ex instanceof UserStoreClientException) {
                            context.setProperty(VoiceOTPConstants.MOBILE_NUMBER_UPDATE_FAILURE, "true");
                            context.setProperty(VoiceOTPConstants.PROFILE_UPDATE_FAILURE_REASON, ex.getMessage());
                        }
                        throw new AuthenticationFailedException("Mobile claim update failed for user: " + username, e);
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

    /**
     * This method will process the otp entered is valid.
     *
     * @param context AuthenticationContext.
     * @param authenticatedUser AuthenticatedUser.
     * @throws AuthenticationFailedException Exception on authentication failure.
     */
    private void processValidUserToken(AuthenticationContext context, AuthenticatedUser authenticatedUser) throws
            AuthenticationFailedException {

        Optional<Object> tokenValidityTime = Optional.ofNullable(context.getProperty(VoiceOTPConstants.
                TOKEN_VALIDITY_TIME));
        if (!tokenValidityTime.isPresent() || !NumberUtils.isNumber(tokenValidityTime.get().toString())) {
            LOG.error("TokenExpiryTime property is not configured in application-authentication.xml or Voice OTP " +
                    "Authenticator UI");
            context.setSubject(authenticatedUser);
            return;
        }

        Optional<Object> otpTokenSentTime = Optional.ofNullable(context.getProperty(VoiceOTPConstants.
                SENT_OTP_TOKEN_TIME));
        if (!otpTokenSentTime.isPresent() || !NumberUtils.isNumber(otpTokenSentTime.get().toString())) {

            LOG.debug("Could not find OTP sent time");

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
                if (LOG.isDebugEnabled()) {
                    LOG.debug("The claim " + VoiceOTPConstants.SAVED_OTP_LIST + " does not contain any values");
                }
                return false;
            }
            if (isBackUpCodeValid(savedOTPs, userToken)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Found saved backup Voice OTP for user :" + authenticatedUser);
                }
                isMatchingToken = true;
                context.setSubject(authenticatedUser);
                savedOTPs = (String[]) ArrayUtils.removeElement(savedOTPs, userToken);
                userRealm.getUserStoreManager().setUserClaimValue(tenantAwareUsername,
                        VoiceOTPConstants.SAVED_OTP_LIST, String.join(",", savedOTPs), null);
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("User entered OTP :" + userToken + " does not match with any of the saved " +
                            "backup codes.");
                }
                context.setProperty(VoiceOTPConstants.CODE_MISMATCH, true);
            }
        } catch (UserStoreException e) {
            LOG.error("Cannot find the user claim for OTP list for user : " + authenticatedUser, e);
        }
        return isMatchingToken;
    }

    /**
     * return whether the backup code entered is valid or not.
     *
     * @param savedOTPs
     * @param userToken
     * @return true or false
     */
    private boolean isBackUpCodeValid(String[] savedOTPs, String userToken) {

        if (StringUtils.isEmpty(userToken)) {
            return false;
        }
        // Check whether the usertoken exists in the saved backup OTP list.
        for (String value : savedOTPs) {
            if (value.equals(userToken)) {
                return true;
            }
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
     * @param username The Username
     * @return The userRealm
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
            throw new AuthenticationFailedException("Cannot find the user realm.", e);
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
     * Get the friendly name of the Authenticator.
     */
    public String getFriendlyName() {

        return VoiceOTPConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get the name of the Authenticator.
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

    /**
     * Is Retry enabled for this authenticator.
     *
     * @return true
     */
    @Override
    protected boolean retryAuthenticationEnabled() {

        return true;
    }

    /**
     * Get the configuration properties of UI.
     * @return list of properties
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<Property>();

        Property voiceUrl = new Property();
        voiceUrl.setName(VoiceOTPConstants.VOICE_URL);
        voiceUrl.setDisplayName("Voice URL");
        voiceUrl.setRequired(true);
        voiceUrl.setDescription("Enter client voice url. If the phone number and otp are in URL, " +
                "specify them as $ctx.num and $ctx.otp");
        voiceUrl.setDisplayOrder(0);
        configProperties.add(voiceUrl);

        Property httpMethod = new Property();
        httpMethod.setName(VoiceOTPConstants.HTTP_METHOD);
        httpMethod.setDisplayName("HTTP Method");
        httpMethod.setRequired(true);
        httpMethod.setDescription("Enter the HTTP Method used by the Voice API");
        httpMethod.setDisplayOrder(1);
        configProperties.add(httpMethod);

        Property headers = new Property();
        headers.setName(VoiceOTPConstants.HEADERS);
        headers.setDisplayName("HTTP Headers");
        headers.setRequired(false);
        headers.setDescription("Enter the headers used by the API separated by comma, with the Header name and value " +
                "separated by \":\". If the phone number and text message are in Headers, specify them as $ctx.num " +
                "and $ctx.otp");
        headers.setDisplayOrder(2);
        configProperties.add(headers);

        Property payload = new Property();
        payload.setName(VoiceOTPConstants.PAYLOAD);
        payload.setDisplayName("HTTP Payload");
        payload.setRequired(false);
        payload.setDescription("Enter the HTTP Payload used by the Voice API. " +
                "If the phone number and otp are " +
                "in Payload, specify them as $ctx.num and $ctx.otp");
        payload.setDisplayOrder(3);
        configProperties.add(payload);

        Property httpResponse = new Property();
        httpResponse.setName(VoiceOTPConstants.HTTP_RESPONSE);
        httpResponse.setDisplayName("HTTP Response Code");
        httpResponse.setRequired(false);
        httpResponse.setDescription("Enter the HTTP response code the API " +
                "sends upon successful call. Leave empty if unknown");
        httpResponse.setDisplayOrder(4);
        configProperties.add(httpResponse);

        Property otpSeparator = new Property();
        otpSeparator.setName(VoiceOTPConstants.OTP_NUMBER_SPLIT_ENABLED);
        otpSeparator.setDisplayName("Enable OTP Separation");
        otpSeparator.setRequired(false);
        otpSeparator.setDescription("Enable this if the otp separation is required, " +
                "which will separate the digits and reads digits separately during the call ");
        otpSeparator.setDefaultValue("TRUE");
        otpSeparator.setType("Boolean");
        otpSeparator.setDisplayOrder(5);
        configProperties.add(otpSeparator);

        Property otpDigitSeparator = new Property();
        otpDigitSeparator.setName(VoiceOTPConstants.OTP_SEPARATOR);
        otpDigitSeparator.setDisplayName("Separate OTP Digits");
        otpDigitSeparator.setRequired(false);
        otpDigitSeparator.setDescription("If the OTP separation is enabled, this will be use " +
                "to separate the Digits of the OTP. This might differ from the OTP provider");
        otpDigitSeparator.setDisplayOrder(6);
        otpDigitSeparator.setDefaultValue(VoiceOTPConstants.DEFAULT_OTP_SEPARATOR);
        configProperties.add(otpDigitSeparator);

        Property divisor = new Property();
        divisor.setName(VoiceOTPConstants.DIVISOR);
        divisor.setDisplayName("Divisor value");
        divisor.setRequired(false);
        divisor.setDescription("This value is use for break the otp numbers. " +
                "Default value is 1. Eg : 123456 if the divisor value is 1," +
                " when reading the otp , the otp would be read as 1 2 3 4 5 6.");
        divisor.setDisplayOrder(7);
        divisor.setDefaultValue(String.valueOf(VoiceOTPConstants.DEFAULT_DIVISOR));
        configProperties.add(divisor);

        Property showErrorInfo = new Property();
        showErrorInfo.setName(VoiceOTPConstants.SHOW_ERROR_INFO);
        showErrorInfo.setDisplayName("Show Detailed Error Information");
        showErrorInfo.setRequired(false);
        showErrorInfo.setDescription("Enter \"true\" if detailed error information from Voice provider needs to be " +
                "displayed in the UI");
        showErrorInfo.setDisplayOrder(8);
        configProperties.add(showErrorInfo);

        Property valuesToBeMasked = new Property();
        valuesToBeMasked.setName(VoiceOTPConstants.VALUES_TO_BE_MASKED_IN_ERROR_INFO);
        valuesToBeMasked.setDisplayName("Mask values in Error Info");
        valuesToBeMasked.setRequired(false);
        valuesToBeMasked.setDescription("Enter comma separated Values " +
                "to be masked by * in the detailed error messages");
        valuesToBeMasked.setDisplayOrder(9);
        configProperties.add(valuesToBeMasked);

        Property mobileNumberRegex = new Property();
        mobileNumberRegex.setName(VoiceOTPConstants.MOBILE_NUMBER_REGEX);
        mobileNumberRegex.setDisplayName("Mobile Number Regex Pattern");
        mobileNumberRegex.setRequired(false);
        mobileNumberRegex.setDescription("Enter regex format to validate mobile number while capture and update " +
                "mobile number.");
        mobileNumberRegex.setDisplayOrder(10);
        configProperties.add(mobileNumberRegex);

        Property regexFailureErrorMessage = new Property();
        regexFailureErrorMessage.setName(VoiceOTPConstants.MOBILE_NUMBER_PATTERN_FAILURE_ERROR_MESSAGE);
        regexFailureErrorMessage.setDisplayName("Regex Violation Error Message");
        regexFailureErrorMessage.setRequired(false);
        regexFailureErrorMessage.setDescription("Enter error message for invalid mobile number patterns.");
        regexFailureErrorMessage.setDisplayOrder(11);
        configProperties.add(regexFailureErrorMessage);

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
     * @param otpToken             The token.
     * @param httpMethod           The http method.
     * @return true or false
     * @throws AuthenticationFailedException
     */
    private boolean getConnection(HttpURLConnection httpConnection, AuthenticationContext context, String headerString,
                                  String payload, String httpResponse, String receivedMobileNumber,
                                  String otpToken, String httpMethod) throws AuthenticationFailedException {

        try {
            httpConnection.setDoInput(true);
            httpConnection.setDoOutput(true);
            String encodedMobileNo = URLEncoder.encode(receivedMobileNumber, CHAR_SET_UTF_8);
            String[] headerArray;
            HashMap<String, Object> headerElementProperties = new HashMap<>();
            if (StringUtils.isNotEmpty(headerString)) {

                LOG.debug("Processing HTTP headers since header string is available.");

                headerString = headerString.trim().replaceAll("\\$ctx.num", receivedMobileNumber).replaceAll(
                        "\\$ctx.otp", otpToken);
                headerArray = headerString.split(",");
                for (String header : headerArray) {
                    String[] headerElements = header.split(":", 2);
                    if (headerElements.length > 1) {
                        httpConnection.setRequestProperty(headerElements[0], headerElements[1]);
                        headerElementProperties.put(headerElements[0], headerElements[1]);
                    } else {
                        LOG.info("Either header name or value not found. Hence not adding header which contains " +
                                headerElements[0]);
                    }
                }
            } else {
                LOG.debug("No configured headers found. Header string is empty.");
            }

            // Processing HTTP Method.
            if (LOG.isDebugEnabled()) {
                LOG.debug("Configured http method is " + httpMethod);
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
                        Here only the mobile number will be encoded,
                        assuming the rest of the content is in correct format.
                        */
                        encodedMobileNo = getEncodedValue(contentType, receivedMobileNumber);
                    } else {
                        if (StringUtils.isNotBlank(contentType) && POST_METHOD.equals(httpMethod) &&
                                (JSON_CONTENT_TYPE).equals(contentType)) {
                            encodedMobileNo = receivedMobileNumber;
                        }
                    }
                    payload = payload.replaceAll("\\$ctx.num", encodedMobileNo).replaceAll("\\$ctx.otp", otpToken);

                    try (OutputStreamWriter writer = new OutputStreamWriter
                            (httpConnection.getOutputStream(), VoiceOTPConstants.CHAR_SET_UTF_8)) {
                        writer.write(payload);
                    } catch (IOException e) {
                        throw new AuthenticationFailedException("Error while posting payload message.", e);
                    }
                }
            }
            if (StringUtils.isNotEmpty(httpResponse)) {
                if (httpResponse.trim().equals(String.valueOf(httpConnection.getResponseCode()))) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Code is successfully sent to the mobile and received expected response code : " +
                                httpResponse);
                    }
                    return true;
                } else {
                    LOG.error("Error while sending Voice: error code is " + httpConnection.getResponseCode()
                            + " and error message is " + httpConnection.getResponseMessage());
                }
            } else {
                if (httpConnection.getResponseCode() == 200 || httpConnection.getResponseCode() == 201
                        || httpConnection.getResponseCode() == 202) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Code is successfully sent to the mobile. Relieved HTTP response code is : " +
                                httpConnection.getResponseCode());
                    }
                    return true;
                } else {
                    context.setProperty(VoiceOTPConstants.ERROR_CODE, httpConnection.getResponseCode() + " : " +
                            httpConnection.getResponseMessage());
                    if (httpConnection.getErrorStream() != null) {
                        String content = getSanitizedErrorInfo(httpConnection.getErrorStream(),
                                context, encodedMobileNo);

                        LOG.error("Error while sending Voice: error code is " + httpConnection.getResponseCode()
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


    /**
     * Get sanitized error information.
     *
     * @param errorStream Input error stream.
     * @param context AuthenticationContext.
     * @param encodedMobileNo Encoded mobile number.
     * @return Sanitized error info.
     * @throws IOException Exception.
     * @throws AuthenticationFailedException Exception on authentication failure.
     */
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
        String decodedMobileNo = URLDecoder.decode(encodedMobileNo, CHAR_SET_UTF_8);
        content = content.replace(decodedMobileNo, screenValue);
        content = maskConfiguredValues(context, content);
        context.setProperty(VoiceOTPConstants.ERROR_INFO, content);

        String errorContent = content;
        if (LOG.isDebugEnabled()) {
            errorContent = contentRaw;
        }
        LOG.error(String.format("Following Error occurred while sending call for user: %s, %s.", context
                .getProperty(VoiceOTPConstants.USER_NAME), errorContent));

        return content;
    }

    /**
     * This will mask the configured values.
     *
     * @param context
     * @param content
     * @return return masked value
     */
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

    /**
     * Convert error input stream to a string.
     *
     * @param errorStream
     * @return
     * @throws IOException
     */
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
     * @param context      The AuthenticationContext
     * @param voiceUrl     The voiceUrl
     * @param httpMethod   The httpMethod
     * @param headerString The headerString
     * @param payload      The payload
     * @param httpResponse The httpResponse
     * @param mobile       The mobile number
     * @param otpToken     The OTP token
     * @return true or false
     * @throws IOException
     * @throws AuthenticationFailedException
     */
    public boolean sendRESTCall(AuthenticationContext context, String voiceUrl, String httpMethod,
                                String headerString, String payload, String httpResponse, String mobile,
                                String otpToken) throws IOException, AuthenticationFailedException {


        LOG.debug("Preparing request for sending out to voice otp provider.");

        HttpURLConnection httpConnection;
        boolean connection;
        String receivedMobileNumber = URLEncoder.encode(mobile, CHAR_SET_UTF_8);

        if (isOTPNumberSplitEnabled(context)) {
            otpToken = splitAndFormatOtp(otpToken, getDivisor(context), context);
        }

        voiceUrl = voiceUrl.replaceAll("\\$ctx.num", receivedMobileNumber)
                .replaceAll("\\$ctx.otp", otpToken);
        URL voiceProviderUrl = null;
        try {
            voiceProviderUrl = new URL(voiceUrl);
        } catch (MalformedURLException e) {
            LOG.error("Error while parsing Voice provider URL: " + voiceUrl, e);
            if (VoiceOTPUtils.isUseInternalErrorCodes(context)) {
                context.setProperty(VoiceOTPConstants.ERROR_CODE,
                        VoiceOTPConstants.ErrorMessage.MALFORMED_URL.getCode());
            } else {
                context.setProperty(VoiceOTPConstants.ERROR_CODE,
                        "The Voice URL does not conform to URL specification.");
            }
            return false;
        }
        String subUrl = voiceProviderUrl.getProtocol();
        if (VoiceOTPConstants.HTTPS.equals(subUrl)) {
            httpConnection = (HttpsURLConnection) voiceProviderUrl.openConnection();
        } else {
            httpConnection = (HttpURLConnection) voiceProviderUrl.openConnection();
        }
        connection = getConnection(httpConnection, context, headerString, payload, httpResponse,
                mobile, otpToken, httpMethod);
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
     * @param userRealm The user Realm.
     * @param username  The username.
     * @return The screen attribute.
     * @throws UserStoreException Exception.
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

    /**
     * Generate masked mobile number.
     *
     * @param context AuthenticationContext.
     * @param screenUserAttributeValue ScreenUserAttributeValue.
     * @param noOfDigits Number of digits
     * @return Masked value.
     */
    private String getMaskedValue(AuthenticationContext context, String screenUserAttributeValue, int noOfDigits) {

        String screenValue;
        String hiddenScreenValue;
        String maskingRegex = VoiceOTPUtils.getScreenValueRegex(context);

        if (StringUtils.isNotEmpty(maskingRegex)) {
            screenValue = screenUserAttributeValue.replaceAll(maskingRegex,
                    VoiceOTPConstants.SCREEN_VALUE_MASKING_CHARACTER);
            return screenValue;
        }

        int screenAttributeLength = screenUserAttributeValue.length();
        // Ensure noOfDigits is not greater than screenAttributeLength.
        noOfDigits = Math.min(noOfDigits, screenAttributeLength);
        if (screenAttributeLength <= noOfDigits && LOG.isDebugEnabled()) {
            LOG.debug("Mobile number length is less than or equal to noOfDigits: " + noOfDigits);
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
     * Get correlation id of current thread.
     *
     * @return correlation-id.
     */
    public static String getCorrelationId() {

        return StringUtils.isBlank(MDC.get(VoiceOTPConstants.CORRELATION_ID_MDC))
                ? UUID.randomUUID().toString() : MDC.get(VoiceOTPConstants.CORRELATION_ID_MDC);
    }

    /**
     * Retrieve the error response code.
     *
     * @param errorMsg
     * @return Error response code
     */
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
            LOG.error("Error while resetting failed Voice OTP attempts.", e);
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
                    break;
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

    /**
     * Get authenticated user claim values.
     *
     * @param authenticatedUser AuthenticatedUser.
     * @return Claim map.
     * @throws AuthenticationFailedException Exception on authentication failure.
     */
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
            LOG.error("Error while reading user claims", e);
            String errorMessage = String.format("Failed to read user claims for user : %s.", authenticatedUser);
            throw new AuthenticationFailedException(errorMessage, e);
        }
        return claimValues;
    }

    /**
     * Update claim values for the authenticated user.
     * @param authenticatedUser
     * @param updatedClaims
     * @throws AuthenticationFailedException
     */
    private void setUserClaimValues(AuthenticatedUser authenticatedUser, Map<String, String> updatedClaims)
            throws AuthenticationFailedException {

        try {
            UserRealm userRealm = getUserRealm(authenticatedUser);
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            userStoreManager.setUserClaimValues(IdentityUtil.addDomainToName(authenticatedUser.getUserName(),
                    authenticatedUser.getUserStoreDomain()), updatedClaims, UserCoreConstants.DEFAULT_PROFILE);
        } catch (UserStoreException e) {
            LOG.error("Error while updating user claims", e);
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
                if (LOG.isDebugEnabled()) {
                    LOG.debug("userStoreManager is null for user: " + username);
                }
                throw new AuthenticationFailedException("userStoreManager is null for user: " + username);
            }
            Map<String, String> claimValues = userStoreManager
                    .getUserClaimValues(tenantAwareUsername, new String[]{VoiceOTPConstants.ACCOUNT_UNLOCK_TIME_CLAIM},
                            null);
            if (claimValues.get(VoiceOTPConstants.ACCOUNT_UNLOCK_TIME_CLAIM) == null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug(String.format("No value configured for claim: %s, of user: %s",
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
     * This method returns the boolean value of the mobile number update failed context property.
     *
     * @param context
     * @return The status of mobile number update failed parameter.
     */
    private boolean isMobileNumberUpdateFailed(AuthenticationContext context) {

        return Boolean.parseBoolean
                (String.valueOf(context.getProperty(VoiceOTPConstants.MOBILE_NUMBER_UPDATE_FAILURE)));
    }

    /**
     * This method returns the boolean value of the code mismatch context property.
     *
     * @param context
     * @return The value of the code mismatch parameter.
     */
    private boolean isCodeMismatch(AuthenticationContext context) {

        return Boolean.parseBoolean(String.valueOf(context.getProperty(VoiceOTPConstants.CODE_MISMATCH)));
    }

    /**
     * Split the given otp by provided divisor.
     * Separate the digits with given separation characters
     *
     * @param context Authentication context.
     * @return split number.
     */
    private String splitAndFormatOtp(String otp, int divisor, AuthenticationContext context) {

        StringBuilder result = new StringBuilder();
        String otpSeparationCharacters = getOTPSeparationCharacters(context);
        for (int i = 0; i < otp.length(); i += divisor) {
            int endIndex = Math.min(i + divisor, otp.length());
            result.append(otp, i, endIndex).append(otpSeparationCharacters);
        }
        return result.substring(0, result.length() - otpSeparationCharacters.length());
    }

    /**
     * This will retrieve the otp separation characters configured in the authenticator UI configurations.
     * If the otp separator is not configured in the UI, it will return the default otp separator.
     *
     * @param context
     * @return Otp separation characters.
     */
    private String getOTPSeparationCharacters(AuthenticationContext context) {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        String otpSeparationCharacters =  authenticatorProperties.get(VoiceOTPConstants.OTP_SEPARATOR);
        if (otpSeparationCharacters != null) {
            return otpSeparationCharacters;
        } else {
            return VoiceOTPConstants.DEFAULT_OTP_SEPARATOR;
        }

    }

    /**
     * Checks whether the otp number split is enabled.
     *
     * @param context Authentication context.
     * @return True if splitting is enabled.
     */
    private boolean isOTPNumberSplitEnabled(AuthenticationContext context) {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();

        String isSplitEnabled = authenticatorProperties.get(VoiceOTPConstants.OTP_NUMBER_SPLIT_ENABLED);

        if (isSplitEnabled != null && !isSplitEnabled.isEmpty()) {
            return Boolean.parseBoolean(isSplitEnabled);
        }
        return true;
    }

    /**
     * Retrieve the divisor value configured in the authenticator configs.
     * If the divisor value is not configured in the UI, it will return default divisor value.
     *
     * @param context
     * @return Divisor value.
     */
    private int getDivisor(AuthenticationContext context) {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        String divisor =  authenticatorProperties.get(VoiceOTPConstants.DIVISOR);
        if (divisor != null && NumberUtils.isNumber(divisor)) {
            return Integer.parseInt(divisor);
        } else {
            return VoiceOTPConstants.DEFAULT_DIVISOR;
        }

    }
}

## VOICE OTP AUTHENTICATOR

The VoiceOTP authenticator allows you to authenticate user via otp which is delivered as a call to the user's mobile number configured.


# File based Configurations 

Add the below configurations to the deployment.toml file 

Authenticator related configurations

```aidl
[authentication.authenticator.voice_otp]
name="VoiceOTP"
enable=true
parameters.VoiceOTPAuthenticationEndpointURL="authenticationendpoint/voiceOtp.jsp"
parameters.VoiceOTPAuthenticationEndpointErrorPage="authenticationendpoint/voiceOtpError.jsp"
parameters.MobileNumberRegPage="authenticationendpoint/voiceMobile.jsp"
parameters.RetryEnable=true
parameters.ResendEnable=true
parameters.BackupCode=true
parameters.VoiceOTPEnableByUserClaim=true
parameters.VoiceOTPMandatory=false
parameters.CaptureAndUpdateMobileNumber=true
parameters.SendOTPDirectlyToMobile=false
parameters.redirectToMultiOptionPageOnFailure=false
parameters.enable_payload_encoding_for_voice_otp=true
```
authenticationendpoint webapp related configurations 

```aidl
[[servlet]]
name="voice_otp.do"
jsp="/voiceOtp.jsp"
url="/voice_otp.do"

[[servlet]]
name="voice_otp_error.do"
jsp="/voiceOtpError.jsp"
url="/voice_otp_error.do"

[[servlet]]
name="voice_mobile.do"
jsp="/voiceMobile.jsp"
url="/voice_mobile.do"
```

# Service provider based configurations

Add the voice otp authenticator to the authentication step from the Local & Outbound Authentication Configuration section.  

![](images/service-provider-outbound-configs.png)

# IdP Configurations

Create a new IdP for the external Voice OTP provider with VoiceOTP authenticator. 

![](images/voice-otp-connector-configs.png)



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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class contains util methods to generate an OTP.
 */
public class OneTimePasswordUtils {

    private static final int[] checkSumDigits = {0, 2, 4, 6, 8, 1, 3, 5, 7, 9};
    private static final Log LOG = LogFactory.getLog(OneTimePasswordUtils.class);

    /**
     * Returns the token generated with random numbers for given size.
     *
     * @param size size.
     * @return generated token.
     */
    public static String getRandomNumber(int size) {

        StringBuilder generatedToken = new StringBuilder();
        try {
            SecureRandom number = SecureRandom.getInstance(VoiceOTPConstants.ALGORITHM_NAME);
            // Generate 20 integers 0..20.
            for (int i = 0; i < size; i++) {
                generatedToken.append(number.nextInt(9));
            }
        } catch (NoSuchAlgorithmException e) {
            LOG.error("Unable to find the Algorithm defined.", e);
        }

        return generatedToken.toString();
    }

    /**
     * Calculates a checksum value based on a given number and the number of digits in that number.
     *
     * @param num    The number to calculate the checksum for
     * @param digits Number of significant places in the number
     * @return The checksum of the number
     */
    public static int calcChecksum(long num, int digits) {

        boolean doubleDigit = true;
        int total = 0;
        while (0 < digits--) {
            int digit = (int) (num % 10);
            num /= 10;
            if (doubleDigit) {
                digit = checkSumDigits[digit];
            }
            total += digit;
            doubleDigit = !doubleDigit;
        }
        int result = total % 10;
        if (result > 0) {
            result = 10 - result;
        }
        return result;
    }

    /**
     * This method uses the JCE to provide the HMAC-SHA-256
     * algorithm. HMAC computes a Hashed Message Authentication Code and in this
     * case SHA256 is the hash algorithm used.
     *
     * @param keyBytes The bytes to use for the HMAC-SHA-256 key
     * @param text     The message or text to be authenticated.
     * @throws NoSuchAlgorithmException If no provider makes either HmacSHA256 or HMAC-SHA-256 digest
     *                                  algorithms available.
     * @throws InvalidKeyException      The secret provided was not a valid HMAC-SHA-256 key.
     */

    public static byte[] hmacShaGenerate(byte[] keyBytes, byte[] text)
            throws NoSuchAlgorithmException, InvalidKeyException {

        Mac hmacSha;
        try {
            hmacSha = Mac.getInstance(VoiceOTPConstants.ALGORITHM_HMAC);
        } catch (NoSuchAlgorithmException nsa) {
            hmacSha = Mac.getInstance(VoiceOTPConstants.ALGORITHM_HMAC_SHA);
        }
        SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");
        hmacSha.init(macKey);
        return hmacSha.doFinal(text);
    }

    /**
     * This method generates an OTP value for the given set of parameters.
     *
     * @param secret           The shared secret
     * @param movingFactor     The counter, or other value that changes on a per use
     *                         basis.
     * @param codeDigits       The number of digits in the OTP, not including the checksum,
     *                         if any.
     * @param addChecksum      A flag that indicates if a checksum digit
     *                         should be appended to the OTP.
     * @param truncationOffset The offset into the MAC result to begin truncation. If this
     *                         value is out of the range of 0 ... 15, then dynamic truncation
     *                         will be used. Dynamic truncation is when the last 4 bits of
     *                         the last byte of the MAC are used to determine the start
     *                         offset.
     * @throws NoSuchAlgorithmException If no provider makes either HmacSHA256 or HMAC-SHA-256 digest
     *                                  algorithms available.
     * @throws InvalidKeyException      The secret provided was not a valid HMAC-SHA-256 key.
     */
    public static String generateOTP(byte[] secret, long movingFactor, int codeDigits, boolean addChecksum,
                                     int truncationOffset) throws NoSuchAlgorithmException, InvalidKeyException {

        // Put movingFactor value into text byte array.
        String result = null;
        int digits = addChecksum ? (codeDigits + 1) : codeDigits;
        byte[] text = new byte[8];
        for (int i = text.length - 1; i >= 0; i--) {
            text[i] = (byte) (movingFactor & 0xff);
            movingFactor >>= 8;
        }
        // Compute hmac hash.
        byte[] hash = hmacShaGenerate(secret, text);

        // Put selected bytes into result int.
        int offset = hash[hash.length - 1] & 0xf;
        if ((0 <= truncationOffset) && (truncationOffset < (hash.length - 4))) {
            offset = truncationOffset;
        }
        int binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);

        int otp = binary % ((int) Math.pow(10, codeDigits));
        if (addChecksum) {
            otp = (otp * 10) + calcChecksum(otp, codeDigits);
        }
        result = Integer.toString(otp);
        while (result.length() < digits) {
            result = "0" + result;
        }
        return result;
    }

    /**
     * This method generates an alphanumeric OTP value for the given set of parameters.
     *
     * @param secret           The shared secret
     * @param movingFactor     The counter, or other value that changes on a per use
     *                         basis.
     * @param codeDigits       The number of digits in the OTP, not including the checksum,
     *                         if any.
     * @param addChecksum      A flag that indicates if a checksum digit
     *                         should be appended to the OTP.
     * @param truncationOffset The offset into the MAC result to begin truncation. If this
     *                         value is out of the range of 0 ... 15, then dynamic truncation
     *                         will be used. Dynamic truncation is when the last 4 bits of
     *                         the last byte of the MAC are used to determine the start
     *                         offset.
     * @throws NoSuchAlgorithmException If no provider makes either HmacSHA256 or HMAC-SHA-256 digest
     *                                  algorithms available.
     * @throws InvalidKeyException      The secret provided was not a valid HMAC-SHA-256 key.
     */
    public static String generateAlphaNumericOTP(byte[] secret, long movingFactor,
                                                 int codeDigits, boolean addChecksum,
                                                 int truncationOffset)
            throws NoSuchAlgorithmException, InvalidKeyException {

        // Put movingFactor value into text byte array.
        String result = null;
        int digits = addChecksum ? (codeDigits + 1) : codeDigits;
        byte[] text = new byte[8];
        for (int i = text.length - 1; i >= 0; i--) {
            text[i] = (byte) (movingFactor & 0xff);
            movingFactor >>= 8;
        }
        // Compute hmac hash.
        byte[] hash = hmacShaGenerate(secret, text);
        // Put selected bytes into result int.
        int offset = hash[hash.length - 1] & 0xf;
        if ((0 <= truncationOffset) && (truncationOffset < (hash.length - 8))) {
            offset = truncationOffset;
        }
        int firstBinary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8) | ((hash[offset + 3] & 0xff));
        int secondBinary = ((hash[offset + 4] & 0x7f) << 24) | ((hash[offset + 5] & 0xff) << 16)
                | ((hash[offset + 6] & 0xff) << 8) | ((hash[offset + 7] & 0xff));
        result = Integer.toString(firstBinary, 36).concat(Integer.toString(secondBinary, 36)).toUpperCase();
        while (result.length() < digits) {
            result = "A" + result;
        }
        result = result.substring(result.length() - digits, result.length());
        return result;
    }

    /**
     * Generate the token.
     *
     * @param key                       The key.
     * @param base                      The base.
     * @param digits                    The number of digits.
     * @param isEnableAlphanumericToken A flag that indicates the token is alphanumeric or not.
     * @return the generated token.
     */
    public String generateToken(String key, String base,
                                int digits, boolean isEnableAlphanumericToken) throws AuthenticationFailedException {

        int truncOffset = 0;
        try {
            if (isEnableAlphanumericToken) {
                return generateAlphaNumericOTP(key.getBytes(), Long.parseLong(base), digits, false, truncOffset);
            } else {
                return generateOTP(key.getBytes(), Long.parseLong(base), digits, false, truncOffset);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new AuthenticationFailedException("Unable to find the SHA256 Algorithm to generate OTP.", e);
        } catch (InvalidKeyException e) {
            throw new AuthenticationFailedException("Given key is inappropriate for initializing the MAC.", e);
        }
    }
}

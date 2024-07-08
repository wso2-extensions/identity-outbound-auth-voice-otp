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

import org.powermock.api.mockito.PowerMockito;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.powermock.reflect.Whitebox;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.authenticator.voiceotp.OneTimePasswordUtils;

import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.mockito.MockitoAnnotations.initMocks;

public class OnetimePasswordTest {
    private OneTimePasswordUtils oneTimePassword;

    @BeforeMethod
    public void setUp() throws Exception {
        oneTimePassword = new OneTimePasswordUtils();
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
    public void testCalcChecksum() {
        Assert.assertEquals(OneTimePasswordUtils.calcChecksum(100, 10), 8);
    }

    @Test
    public void testGetRandomNumber() {
        Assert.assertNotNull(OneTimePasswordUtils.getRandomNumber(10));
    }

    @Test
    public void testHmacShaGenerate() throws InvalidKeyException, NoSuchAlgorithmException {
        String input = "Hello World";
        byte[] bytes = input.getBytes(Charset.forName("UTF-8"));
        byte[] answer = OneTimePasswordUtils.hmacShaGenerate(bytes, bytes);
        String s = new String(answer, Charset.forName("UTF-8"));
        Assert.assertNotNull(OneTimePasswordUtils.hmacShaGenerate(bytes, bytes));
    }

    @Test
    public void testGenerateTokenWithNumericToken() throws Exception {
        OneTimePasswordUtils otp = PowerMockito.spy(oneTimePassword);
        Assert.assertEquals(Whitebox.invokeMethod(otp, "generateToken", "Hello", "32", 10, false),
                "0020315280");
    }

    @Test
    public void testGenerateTokenWithAlphaNumericToken() throws Exception {
        OneTimePasswordUtils otp = PowerMockito.spy(oneTimePassword);
        Assert.assertEquals(Whitebox.invokeMethod(otp, "generateToken", "Hello", "32", 10, true),
                "3FDC3J6089");
    }
}

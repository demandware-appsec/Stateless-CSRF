/*
 * Copyright 2016 Demandware Inc. Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions and limitations under the
 * License.
 */
package com.demandware.appsec.csrf;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.security.SecureRandom;
import java.util.Arrays;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class StatelessCSRFTokenManagerTest
{
    private StatelessCSRFTokenManager csrfMgrDefault;

    private StatelessCSRFTokenManager csrfMgrLogs;

    private CSRFHandlerLog csrfHandler;

    private static final String SESSION_ID = "QUxMIFlPVVIgQkFTRSBBUkUgQkVMT05HIFRPIFVTIQ==";

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Before
    public void setUp()
    {
        // this mgr throws exceptions
        this.csrfMgrDefault = new StatelessCSRFTokenManager();
        // this logs to custom logger
        this.csrfMgrLogs = new StatelessCSRFTokenManager();
        // the custom logger
        this.csrfHandler = new CSRFHandlerLog();
        this.csrfMgrLogs.setErrorHandler( csrfHandler );
    }

    static class CSRFHandlerLog
        implements ICSRFErrorHandler
    {
        StringBuilder logger;

        CSRFHandlerLog()
        {
            logger = new StringBuilder();
        }

        public void handleFatalException( String error, Exception e )
        {
            logger.append( error );
            if ( e != null )
            {
                logger.append( e.getMessage() );
            }
        }

        public String getString()
        {
            return logger.toString();
        }

        public void clearLog()
        {
            logger.setLength( 0 );
        }

        public void handleValidationError( String message )
        {
            handleFatalException( message, null );
        }

        public void handleInternalError( String message )
        {
            handleFatalException( message, null );
        }
    }

    // Default case. Test token generates and validates
    @Test
    public void testCorrectTokenGeneration()
    {
        String tokenName = this.csrfMgrDefault.getCSRFTokenName();
        String tokenValue = this.csrfMgrDefault.generateToken( SESSION_ID );
        
        System.out.println( tokenValue );
        assertNotNull( tokenName );
        assertNotNull( tokenValue );

        assertTrue( this.csrfMgrDefault.validateToken( tokenValue, SESSION_ID ) );
    }

    // Extra data added to token, generate/validate
    @Test
    public void testCorrectTokenGenerationExtraData()
    {
        String[] additionalData = { "sometoken", "adifferenttoken" };
        String tokenName = this.csrfMgrDefault.getCSRFTokenName();
        String tokenValue = this.csrfMgrDefault.generateToken( SESSION_ID, additionalData );
        assertNotNull( tokenName );
        assertNotNull( tokenValue );

        assertTrue( this.csrfMgrDefault.validateToken( tokenValue, SESSION_ID, additionalData ) );
    }
    
    // Extra data added to token, but validate is different extra data
    @Test
    public void testBadTokenGenerationWrongExtraData()
    {
        String[] additionalData = { "sometoken", "adifferenttoken" };
        String[] wrongAdditionalData = { "sometoken", "nottherightdifferenttoken" };

        String tokenName = this.csrfMgrDefault.getCSRFTokenName();
        String tokenValue = this.csrfMgrDefault.generateToken( SESSION_ID, additionalData );
        assertNotNull( tokenName );
        assertNotNull( tokenValue );

        assertFalse( this.csrfMgrDefault.validateToken( tokenValue, SESSION_ID, wrongAdditionalData ) );
    }

    // Extra data is null. Should generate and validate anyway
    @Test
    public void testCorrectTokenGenerationWithNullExtraData()
    {
        String[] additionalData = null;

        String tokenName = this.csrfMgrDefault.getCSRFTokenName();
        String tokenValue = this.csrfMgrDefault.generateToken( SESSION_ID, additionalData );
        assertNotNull( tokenName );
        assertNotNull( tokenValue );

        assertTrue( this.csrfMgrDefault.validateToken( tokenValue, SESSION_ID, additionalData ) );
    }

    // generate with 2 extra data, validate with only one
    @Test
    public void testBadTokenGenerationWithDifferentAmountExtraData()
    {
        String[] additionalData = { "sometoken", "adifferenttoken" };
        String[] wrongAdditionalData = { "sometoken" };

        String tokenName = this.csrfMgrDefault.getCSRFTokenName();
        String tokenValue = this.csrfMgrDefault.generateToken( SESSION_ID, additionalData );
        assertNotNull( tokenName );
        assertNotNull( tokenValue );

        assertFalse( this.csrfMgrDefault.validateToken( tokenValue, SESSION_ID, wrongAdditionalData ) );
    }

    // generate with no extra data, validate with extra data
    @Test
    public void testBadTokenGenerationWithDifferentAmountExtraDataValidation()
    {
        String[] additionalData = { "sometoken", "adifferenttoken" };

        String tokenName = this.csrfMgrDefault.getCSRFTokenName();
        String tokenValue = this.csrfMgrDefault.generateToken( SESSION_ID );
        assertNotNull( tokenName );
        assertNotNull( tokenValue );

        assertFalse( this.csrfMgrDefault.validateToken( tokenValue, SESSION_ID, additionalData ) );
    }

    // change setter/getters for expiration, clock, and token name
    @Test
    public void testDifferentDefaults()
    {
        long expiry = 10000000L;
        String name = "foobar";

        StatelessCSRFTokenManager mgr = new StatelessCSRFTokenManager();
        mgr.setAllowedExpiry( expiry );
        mgr.setCSRFTokenName( name );

        String tokenName = mgr.getCSRFTokenName();
        assertEquals( name, tokenName );
        assertEquals( expiry, mgr.getAllowedExpiry() );

        String tokenValue = mgr.generateToken( SESSION_ID );

        assertTrue( mgr.validateToken( tokenValue, SESSION_ID ) );
    }

    // with static SR, still get different tokens, if SR and time stop, generate same token
    @Test
    public void testWithBrokenRandoms()
        throws InterruptedException
    {
        SecureRandom badRand = new SecureRandom()
        {

            private static final long serialVersionUID = 1L;

            @Override
            public void nextBytes( byte[] bytes )
            {
                Arrays.fill( bytes, (byte) 0 );
            }
        };

        String token1 = new StatelessCSRFTokenManager( badRand ).generateToken( SESSION_ID );
        Thread.sleep( 100L );

        final long now = System.currentTimeMillis();

        StatelessCSRFTokenManager frozenInTime = new StatelessCSRFTokenManager( badRand )
        {
            protected long getCurrentTime()
            {
                return now;
            }
        };

        String token2 = frozenInTime.generateToken( SESSION_ID );
        String token3 = frozenInTime.generateToken( SESSION_ID );

        assertFalse( token1.equals( token2 ) );
        assertEquals( token2, token3 );
    }

    // null check for error handler
    @Test
    public void testBadHandler()
    {
        this.exception.expect( IllegalArgumentException.class );
        new StatelessCSRFTokenManager().setErrorHandler( null );
    }

    // negative expiration check for expiry
    @Test
    public void testBadExpiry()
    {
        this.exception.expect( IllegalArgumentException.class );
        new StatelessCSRFTokenManager().setAllowedExpiry( -1L );
    }

    // null check for token name
    @Test
    public void testBadTokenName()
    {
        this.exception.expect( IllegalArgumentException.class );
        new StatelessCSRFTokenManager().setCSRFTokenName( null );
    }

    // null check for null session
    @Test
    public void testBadSessionValidate()
    {
        this.exception.expect( IllegalArgumentException.class );
        StatelessCSRFTokenManager mgr = new StatelessCSRFTokenManager();
        mgr.validateToken( mgr.generateToken( SESSION_ID ), null );
    }

    //////////////////
    // Tests with Default Handler
    //////////////////

    @Test
    public void testNullSessionIDDefault()
    {
        this.exception.expect( IllegalArgumentException.class );
        this.csrfMgrDefault.generateToken( null );
    }

    @Test
    public void testEmptySessionIDDefault()
    {
        assertNull( this.csrfMgrDefault.generateToken( "" ) );
    }

    @Test
    public void testShortSessionIDDefault()
    {
        assertNull( this.csrfMgrDefault.generateToken( "a" ) );
    }

    @Test
    public void testExpiredValidTokenDefault()
        throws InterruptedException
    {

        StatelessCSRFTokenManager curmgr = new StatelessCSRFTokenManager();
        curmgr.setAllowedExpiry( 1L ); // set expiration very low

        String tokenName = curmgr.getCSRFTokenName();
        String tokenValue = curmgr.generateToken( SESSION_ID );

        assertNotNull( tokenName );
        assertNotNull( tokenValue );

        Thread.sleep( 50L ); // wait a significant time after expiry

        assertFalse( curmgr.validateToken( tokenValue, SESSION_ID ) );
    }

    @Test
    public void testInvalidTokensDefault()
    {
        String tokenName = this.csrfMgrDefault.getCSRFTokenName();
        String tokenValue = this.csrfMgrDefault.generateToken( SESSION_ID );
        String originalValue = tokenValue;
        assertNotNull( tokenName );
        assertNotNull( tokenValue );

        assertTrue( this.csrfMgrDefault.validateToken( tokenValue, SESSION_ID ) );

        //@formatter:off
        String[] invalid = 
                    { 
                        "foobar", 
                        "", 
                        originalValue + "aaaa", 
                        null,
                        this.csrfMgrDefault.generateToken( SESSION_ID+"|a" )
                    };
        //@formatter:on

        for ( String bad : invalid )
        {
            try
            {
                assertFalse( bad, this.csrfMgrDefault.validateToken( bad, SESSION_ID ) );
            }
            catch ( SecurityException e )
            {
                // ok
            }
        }
    }

    @Test
    public void testDifferentSessionInvalidDefault()
    {
        String tokenName = this.csrfMgrDefault.getCSRFTokenName();
        String tokenValue = this.csrfMgrDefault.generateToken( SESSION_ID );

        String sessionid = "ABCDEF0123456789";

        assertNotNull( tokenName );
        assertNotNull( tokenValue );

        assertFalse( this.csrfMgrDefault.validateToken( tokenValue, sessionid ) );
    }

    //////////////////
    // Tests with Subclass logger
    //////////////////

    @Test
    public void testNullSessionIDLogger()
    {
        this.exception.expect( IllegalArgumentException.class );
        this.csrfMgrLogs.generateToken( null );
    }

    @Test
    public void testEmptySessionIDLogger()
    {
        assertNull( this.csrfMgrLogs.generateToken( "" ) );
    }

    @Test
    public void testShortSessionIDLogger()
    {
        assertNull( this.csrfMgrLogs.generateToken( "a" ) );
    }

    @Test
    public void testExpiredValidTokenLogger()
        throws InterruptedException
    {

        StatelessCSRFTokenManager mgr = new StatelessCSRFTokenManager();
        mgr.setErrorHandler( csrfHandler );
        csrfHandler.clearLog();

        mgr.setAllowedExpiry( 1L ); // set expiration very low

        String tokenName = mgr.getCSRFTokenName();
        String tokenValue = mgr.generateToken( SESSION_ID );

        assertNotNull( tokenName );
        assertNotNull( tokenValue );

        Thread.sleep( 50L ); // wait a significant time after expiry

        assertFalse( mgr.validateToken( tokenValue, SESSION_ID ) );
        assertTrue( csrfHandler.getString().contains( "expired" ) );

    }

    @Test
    public void testInvalidTokensLogger()
    {
        this.csrfHandler.clearLog();
        String tokenName = this.csrfMgrLogs.getCSRFTokenName();
        String tokenValue = this.csrfMgrLogs.generateToken( SESSION_ID );
        String originalValue = tokenValue;
        assertNotNull( tokenName );
        assertNotNull( tokenValue );

        assertTrue( this.csrfMgrLogs.validateToken( tokenValue, SESSION_ID ) );

        //@formatter:off
        String[] invalid = 
                    { 
                        "foobar", 
                        "", 
                        originalValue + "aaaa", 
                        null,
                        this.csrfMgrDefault.generateToken( SESSION_ID+"|a" )
                    };
        //@formatter:on

        for ( String bad : invalid )
        {
            assertFalse( this.csrfMgrLogs.validateToken( bad, SESSION_ID ) );
        }
    }

    @Test
    public void testDifferentSessionInvalidLogger()
    {
        this.csrfHandler.clearLog();
        String tokenName = this.csrfMgrLogs.getCSRFTokenName();
        String tokenValue = this.csrfMgrLogs.generateToken( SESSION_ID );

        char old = SESSION_ID.charAt( SESSION_ID.length() - 1 );
        String sessionid = SESSION_ID.substring( 0, SESSION_ID.length() - 1 ) + ( old + 1 );

        assertNotNull( tokenName );
        assertNotNull( tokenValue );

        assertFalse( this.csrfMgrLogs.validateToken( tokenValue, sessionid ) );
        assertTrue( this.csrfHandler.getString(), this.csrfHandler.getString().contains( "session ids don't match" ) );
    }
}

/*
 * Copyright 2016 Demandware Inc. Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions and limitations under the
 * License.
 */
package com.demandware.appsec.csrf;

import static org.junit.Assert.*;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Arrays;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class _CSRFTokenManager
{
    private CSRFTokenManager csrfMgrExceptions;

    private CSRFTokenManager csrfMgrLogs;

    private CSRFHandlerLog csrfHandler;

    private static final String SESSION_ID = "QUxMIFlPVVIgQkFTRSBBUkUgQkVMT05HIFRPIFVTIQ==";

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Before
    public void setUp()
    {
        this.csrfMgrExceptions = new CSRFTokenManager();
        this.csrfMgrLogs = new CSRFTokenManager();
        this.csrfHandler = new CSRFHandlerLog();
        this.csrfMgrLogs.setErrorHandler( csrfHandler );
    }

    class CSRFHandlerLog
        extends CSRFErrorHandler
    {
        StringBuilder logger;

        CSRFHandlerLog()
        {
            logger = new StringBuilder();
        }

        @Override
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

        @Override
        public void handleValidationError( String message )
        {
            handleFatalException( message, null );
        }

        @Override
        public void handleInternalError( String message )
        {
            handleFatalException( message, null );
        }
    }

    @Test
    public void testCorrectTokenGeneration()
    {
        String tokenName = this.csrfMgrExceptions.getCSRFTokenName();
        String tokenValue = this.csrfMgrExceptions.generateToken( SESSION_ID );
        assertNotNull( tokenName );
        assertNotNull( tokenValue );

        assertTrue( this.csrfMgrExceptions.validateCSRFToken( tokenValue, SESSION_ID ) );
    }

    @Test
    public void testDifferentDefaults()
    {
        long expiry = 10000000L;
        String name = "foobar";

        Clock clk = Clock.systemUTC();

        CSRFTokenManager mgr = new CSRFTokenManager( null, clk );
        mgr.setAllowedExpiry( expiry );
        mgr.setCSRFTokenName( name );

        String tokenName = mgr.getCSRFTokenName();
        assertEquals( name, tokenName );
        assertEquals( expiry, mgr.getAllowedExpiry() );

        String tokenValue = mgr.generateToken( SESSION_ID );

        clk = Clock.offset( clk, Duration.ofSeconds( this.csrfMgrExceptions.getAllowedExpiry() ) );

        assertTrue( mgr.validateCSRFToken( tokenValue, SESSION_ID ) );

    }

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

        String token1 = new CSRFTokenManager( badRand ).generateToken( SESSION_ID );
        Thread.sleep( 100L );
        Clock clk = Clock.fixed( Instant.now(), ZoneId.systemDefault() );
        String token2 = new CSRFTokenManager( badRand, clk ).generateToken( SESSION_ID );
        String token3 = new CSRFTokenManager( badRand, clk ).generateToken( SESSION_ID );

        assertFalse( token1.equals( token2 ) );
        assertEquals( token2, token3 );
    }

    @Test
    public void testBadHandler()
    {
        this.exception.expect( IllegalArgumentException.class );
        new CSRFTokenManager().setErrorHandler( null );
    }

    @Test
    public void testBadExpiry()
    {
        this.exception.expect( IllegalArgumentException.class );
        new CSRFTokenManager().setAllowedExpiry( -1L );
    }

    @Test
    public void testBadTokenName()
    {
        this.exception.expect( IllegalArgumentException.class );
        new CSRFTokenManager().setCSRFTokenName( null );
    }
    
    @Test
    public void testBadSessionValidate()
    {
        this.exception.expect( IllegalArgumentException.class );
        CSRFTokenManager mgr = new CSRFTokenManager();
        mgr.validateCSRFToken( mgr.generateToken( SESSION_ID ), null );
    }

    //////////////////
    // Tests with Default Handler
    //////////////////

    @Test
    public void testNullSessionIDDefault()
    {
        this.exception.expect( IllegalArgumentException.class );
        this.csrfMgrExceptions.generateToken( null );
    }

    @Test
    public void testEmptySessionIDDefault()
    {
        assertNull( this.csrfMgrExceptions.generateToken( "" ) );
    }

    @Test
    public void testShortSessionIDDefault()
    {
        assertNull( this.csrfMgrExceptions.generateToken( "a" ) );
    }

    @Test
    public void testExpiredValidTokenDefault()
        throws InterruptedException
    {

        CSRFTokenManager curmgr = new CSRFTokenManager();
        curmgr.setAllowedExpiry( 1L ); // set expiration very low

        String tokenName = curmgr.getCSRFTokenName();
        String tokenValue = curmgr.generateToken( SESSION_ID );

        assertNotNull( tokenName );
        assertNotNull( tokenValue );

        Thread.sleep( 50L ); // wait a significant time after expiry

        assertFalse( curmgr.validateCSRFToken( tokenValue, SESSION_ID ) );
    }

    @Test
    public void testInvalidTokensDefault()
    {
        String tokenName = this.csrfMgrExceptions.getCSRFTokenName();
        String tokenValue = this.csrfMgrExceptions.generateToken( SESSION_ID );
        String originalValue = tokenValue;
        assertNotNull( tokenName );
        assertNotNull( tokenValue );

        assertTrue( this.csrfMgrExceptions.validateCSRFToken( tokenValue, SESSION_ID ) );

        //@formatter:off
        String[] invalid = 
                    { 
                        originalValue.substring( 0, originalValue.indexOf( "|" ) ) + "|foobar",
                        "foobar" + originalValue.substring( originalValue.indexOf( "|" ) ), 
                        "", 
                        originalValue + "|", 
                        "|",
                        originalValue.replace( "|", "||" ),
                        null,
                        this.csrfMgrExceptions.generateToken( SESSION_ID+"|a" )
                    };
        //@formatter:on

        for ( String bad : invalid )
        {
            assertFalse( this.csrfMgrExceptions.validateCSRFToken( bad, SESSION_ID ) );
        }
    }

    @Test
    public void testDifferentSessionInvalidDefault()
    {
        String tokenName = this.csrfMgrExceptions.getCSRFTokenName();
        String tokenValue = this.csrfMgrExceptions.generateToken( SESSION_ID );

        char old = SESSION_ID.charAt( SESSION_ID.length() - 1 );
        String sessionid = SESSION_ID.substring( 0, SESSION_ID.length() - 1 ) + ( old + 1 );

        assertNotNull( tokenName );
        assertNotNull( tokenValue );

        assertFalse( this.csrfMgrExceptions.validateCSRFToken( tokenValue, sessionid ) );
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

        CSRFTokenManager mgr = new CSRFTokenManager();
        mgr.setErrorHandler( csrfHandler );
        csrfHandler.clearLog();

        mgr.setAllowedExpiry( 1L ); // set expiration very low

        String tokenName = mgr.getCSRFTokenName();
        String tokenValue = mgr.generateToken( SESSION_ID );

        assertNotNull( tokenName );
        assertNotNull( tokenValue );

        Thread.sleep( 50L ); // wait a significant time after expiry

        assertFalse( mgr.validateCSRFToken( tokenValue, SESSION_ID ) );
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

        assertTrue( this.csrfMgrLogs.validateCSRFToken( tokenValue, SESSION_ID ) );

        //@formatter:off
        String[] invalid = 
                    { 
                        originalValue.substring( 0, originalValue.indexOf( "|" ) ) + "|foobar",
                        "foobar" + originalValue.substring( originalValue.indexOf( "|" ) ), 
                        "", 
                        originalValue + "|", 
                        "|",
                        originalValue.replace( "|", "||" ),
                        null,
                        this.csrfMgrLogs.generateToken( SESSION_ID+"|a" )
                    };
        //@formatter:on

        for ( String bad : invalid )
        {
            assertFalse( this.csrfMgrLogs.validateCSRFToken( bad, SESSION_ID ) );
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

        assertFalse( this.csrfMgrLogs.validateCSRFToken( tokenValue, sessionid ) );
        assertTrue( this.csrfHandler.getString(), this.csrfHandler.getString().contains( "session ids don't match" ) );
    }
}

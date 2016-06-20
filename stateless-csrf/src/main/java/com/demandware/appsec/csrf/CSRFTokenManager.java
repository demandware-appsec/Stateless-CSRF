/*
 * Copyright 2016 Demandware Inc. Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions and limitations under the
 * License.
 */
package com.demandware.appsec.csrf;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;

/**
 * <p>
 * The CSRFTokenManager is in charge of generating and validating CSRF tokens. This CSRF defense allows applications to
 * generate <a href="http://www.corej2eepatterns.com/Design/PresoDesign.htm"> synchronizer tokens</a> as recommended by
 * <a href= "https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet"> OWASP</a>. These
 * tokens are semi-stateless (tied to session, but not stored anywhere) and so can be generated wherever in the
 * application and validated wherever.
 * </p>
 * <p>
 * In the default case, CSRF tokens are generated in this manner: <br>
 * </p>
 * <ol>
 * <li>Given a SessionID (must be at least 16 bytes long), first generate a TokenID from a {@linkplain SecureRandom}
 * </li>
 * <li>Next, get the current timestamp</li>
 * <li>Create the text to be encrypted, cryptText, as SessionID|timestamp</li>
 * <li>Use the TokenID as an IV and the first 16 bytes of the SessionID as key to encrypt the cryptText</li>
 * <li>Then prepend the TokenID to the encrypted value. This is the Token</li>
 * </ol>
 * <p>
 * In the default case, CSRF tokens are validated in this manner: <br>
 * </p>
 * <ol>
 * <li>Given a SessionID and a Token, first split the token into TokenID and encrypted text</li>
 * <li>Next, decrypt the encrypted text using the first 16 bytes of the SessionID as key and TokenID as IV</li>
 * <li>Split the resulting cryptText into SessionID and timestamp</li>
 * <li>validate that the full SessionID matches the decrypted version (not just first 16 bytes)</li>
 * <li>validate that the timestamp is within the expiration time from now</li>
 * </ol>
 * <p>
 * The generation and validation methods also allow application developers to specify further items to be encrypted (in
 * addition to the sessionID and timestamp). These items are validated in their supplied order, so developers should
 * take care to maintain the same order during validation as was used in generation.
 * </p>
 * <p>
 * <b>Note:</b> By default, a {@linkplain CSRFErrorHandler} is assigned to the Manager. This handler writes all data to
 * SysErr during generation and validation when an error has occurred or validation has failed
 * </p>
 *
 * @author Chris Smith
 */
public class CSRFTokenManager
{

    /*
     * 30 minutes in milliseconds
     */
    public static final long DEFAULT_EXPIRY = 30 * 60 * 1000;

    public static final String DEFAULT_CSRF_TOKEN_NAME = "csrf_token";

    /*
     * size of the generated token's ID (not the final token). it must be 16
     * bytes long at least (after hex encoding)
     */
    private static final int TOKEN_SIZE = 8;

    /*
     * Default required for AES/GCM
     */
    private static final int KEY_SIZE = 16;

    /*
     * Default required for AES/GCM
     */
    private static final int GCM_TAG_BITS = 128;

    /*
     * Default required for AES/GCM
     */
    private static final int PARAMETER_SPEC_SIZE = 16;

    private static final String SEPARATOR = "|";

    /////////////////////
    // Member variables
    /////////////////////

    /*
     * a strong random to use to generate Token IDs to be used as IVs 
     */
    private SecureRandom random;

    /*
     * Stores a token name only as a convenience
     */
    private String csrfTokenName;

    /*
     * Time in milliseconds for the token to persist
     */
    private long expiry;

    /*
     * manages all error conditions. Default is to write to syserr
     */
    private CSRFErrorHandler handler;

    /**
     * Create a new {@linkplain CSRFTokenManager} with all defaults
     */
    public CSRFTokenManager()
    {
        this( null );
    }

    /**
     * Create a new {@linkplain CSRFTokenManager} with all defaults and use the provided {@linkplain SecureRandom}
     * 
     * @param random a {@linkplain SecureRandom} instance to use in generating random tokens
     */
    public CSRFTokenManager( SecureRandom random )
    {
        if ( random == null )
        {
            this.random = new SecureRandom();
        }
        else
        {
            this.random = random;
        }

        this.csrfTokenName = DEFAULT_CSRF_TOKEN_NAME;
        this.expiry = DEFAULT_EXPIRY;
        this.handler = new DefaultCSRFErrorHandler();
    }

    /**
     * Configure this object to use a different {@linkplain CSRFErrorHandler}
     * 
     * @param handler the {@linkplain CSRFErrorHandler} to use
     * @throws IllegalArgumentException if the handler is null
     */
    public void setErrorHandler( CSRFErrorHandler handler )
        throws IllegalArgumentException
    {
        if ( handler == null )
        {
            throw new IllegalArgumentException( "Provided handler is null" );
        }

        this.handler = handler;
    }

    /**
     * Returns the assigned name for CSRF tokens
     *
     * @return CSRF Token parameter name
     */
    public String getCSRFTokenName()
    {
        return this.csrfTokenName;
    }

    /**
     * Configure a new token name. This is a convenience method
     * 
     * @param tokenName the new name for the token
     * @throws IllegalArgumentException if the tokenName is null
     */
    public void setCSRFTokenName( String tokenName )
        throws IllegalArgumentException
    {
        if ( tokenName == null )
        {
            throw new IllegalArgumentException( "Provided CSRF Token name is null" );
        }

        this.csrfTokenName = tokenName;
    }

    /**
     * Returns the expiration time in milliseconds for CSRF Tokens
     *
     * @return CSRF Token parameter expiration in millis
     */
    public long getAllowedExpiry()
    {
        return this.expiry;
    }

    /**
     * Configure a new expiration time on tokens. This takes effect immediately on all outstanding tokens. e.g. if the
     * old expiry were 10 mins and the new expiry is 20 mins, all tokens generated 19 mins ago are now valid, even
     * though they weren't before the expiration was reset. 
     * 
     * @param expiry the new expiration time in milliseconds
     * @throws IllegalArgumentException if the expiration time is less that 0
     */
    public void setAllowedExpiry( long expiry )
        throws IllegalArgumentException
    {
        if ( expiry < 0L )
        {
            throw new IllegalArgumentException( "Provided token expiration is negative" );
        }

        this.expiry = expiry;
    }

    /**
     * Builds a secure token used to protect against CSRF attacks. Additional data may be used to further lengthen the
     * resulting token
     *
     * @param sessionID the sessionID of this request
     * @param otherData (Optional) any other strings that should be used to generate the token. See class definition.
     * @return a new CSRF token value for this session
     * @throws IllegalArgumentException if the sessionID is null
     */
    public String generateToken( String sessionID, String... otherData )
        throws IllegalArgumentException
    {
        if ( sessionID == null )
        {
            throw new IllegalArgumentException( "Token cannot be generated from null sessionID" );
        }

        if ( sessionID.length() < KEY_SIZE )
        {
            this.handler.handleInternalError( "Token cannot be generated from session size less than " + KEY_SIZE );
            return null;
        }

        String tokenId = generateID( TOKEN_SIZE );

        String token = generateTokenInternal( tokenId, sessionID, otherData );

        String finalToken = new StringBuilder().append( tokenId ).append( SEPARATOR ).append( token ).toString();

        return finalToken;
    }

    /**
     * Generate a random hex string of some given size
     *
     * @param size the number of bytes the ID should contain
     * @return a random hex string
     */
    private String generateID( int size )
    {
        byte[] bytes = new byte[size];
        random.nextBytes( bytes );
        // hex is used to maintain entropy of the generated id
        return Hex.encodeHexString( bytes );
    }

    /**
     * Generate a key based on a random id, session id, and current time with optional other data added
     *
     * @param id a random id
     * @param sessionID the session of the current request
     * @param dataToCrypt (Optional) any other strings that should be used to generate the token. See class definition.
     * @return a generated stateless token, or null, if an error occurred
     */
    private String generateTokenInternal( String id, String sessionID, String... dataToCrypt )
    {
        String tokenString;

        String timestamp = Long.toString( getCurrentTime() );

        // always begin with session and timestamp
        StringBuilder sbCryptText = new StringBuilder();
        sbCryptText.append( sessionID ).append( SEPARATOR ).append( timestamp );

        // if ontherdata supplied, append it to the sbCryptText in the same format, maintaining ordering
        if ( dataToCrypt != null )
        {
            int len = dataToCrypt.length;
            for ( int i = 0; i < len; i++ )
            {
                sbCryptText.append( SEPARATOR ).append( dataToCrypt[i] );
            }
        }

        String cryptText = sbCryptText.toString();
        String key = sessionID;
        String iv = id;

        byte[] encryptedValue;
        try
        {
            encryptedValue = crypt( key, iv, cryptText.getBytes( "UTF-8" ), Cipher.ENCRYPT_MODE );
            tokenString = Hex.encodeHexString( encryptedValue );
        }
        catch ( Exception e )
        {
            String error = new StringBuilder().append( "CSRF Token generation failed for tokenID " ).append( id )
                .append( ", and sessionID " ).append( sessionID ).append( " with exception" ).toString();

            this.handler.handleFatalException( error, e );

            tokenString = null;
        }

        return tokenString;
    }

    /**
     * Ensures that the supplied token is a valid csrf token. Valid tokens are made up of the current session, randomly
     * generated token, timestamp, and any other data supplied. The timestamp must be within some number of milliseconds
     * before now based on the {@linkplain #getAllowedExpiry()}
     *
     * @param token the incoming token to test against
     * @param sessionID the sessionID of the current request
     * @param otherData (Optional) any other strings that should be used to validate the token. See class definition.
     * @return true if the token is valid for this sessionID. false otherwise
     * @throws IllegalArgumentException if the session ID is null
     */
    public boolean validateToken( String token, String sessionID, String... otherData )
        throws IllegalArgumentException
    {
        if ( token == null || !token.contains( SEPARATOR ) )
        {
            this.handler.handleInternalError( "CSRF token is not be properly formed" );
            return false;
        }

        if ( sessionID == null )
        {
            throw new IllegalArgumentException( "Provided session id is null" );
        }

        int sep = token.indexOf( SEPARATOR );
        String tokenId = token.substring( 0, sep );
        String tokenString = token.substring( sep + 1 );

        boolean isValid = validateTokenInternal( tokenId, sessionID, tokenString, otherData );

        if ( !isValid )
        {
            this.handler.handleValidationError( "Could not validate CSRF token. CSRF attack detected" );
        }

        return isValid;
    }

    /**
     * Tests the given token id + string for validity. Also does internal checking of string to attempt to detect
     * tampering
     *
     * @param tokenId the random ID to use in key generation
     * @param sessionID the session of the current request
     * @param dataToCrypt (Optional) any other strings that should be used to validate the token. See class definition.
     * @param tokenString the token value to check against
     * @return true if the token is valid, false otherwise
     */
    private boolean validateTokenInternal( String tokenId, String sessionID, String tokenString, String... dataToCrypt )
    {
        boolean result = false;

        long timestamp = getCurrentTime();

        String key = sessionID;
        String iv = tokenId;

        try
        {
            byte[] encryptedValue = Hex.decodeHex( tokenString.toCharArray() );

            byte[] decrypted = crypt( key, iv, encryptedValue, Cipher.DECRYPT_MODE );
            String cryptText = new String( decrypted, "UTF-8" );
            String[] decryptParts = cryptText.split( Pattern.quote( SEPARATOR ) );

            int cryptlen = dataToCrypt == null ? 0 : dataToCrypt.length;

            // 2 guaranteed pieces (session and timestamp) plus the additional data
            if ( decryptParts.length == ( 2 + cryptlen ) )
            {
                String decryptedSession = decryptParts[0];
                long decryptedTimestamp = Long.parseLong( decryptParts[1] );

                /*
                 * verify sessions match verify that the timestamp in the 
                 * token is within the permitted time allowance and verify 
                 * all other possible data matches in order
                 */
                if ( !decryptedSession.equals( sessionID ) )
                {
                    String error = new StringBuilder().append( "CSRF Token session ids don't match. Expected: " )
                        .append( sessionID ).append( "but received: " ).append( decryptedSession ).toString();

                    this.handler.handleValidationError( error );
                }
                else if ( ( decryptedTimestamp + getAllowedExpiry() ) < timestamp )
                {
                    String error = new StringBuilder().append( "CSRF Token has expired. Expected: " )
                        .append( timestamp ).append( " but received: " ).append( decryptedTimestamp ).toString();

                    this.handler.handleValidationError( error );
                }
                else if ( cryptlen > 0 )
                {
                    for ( int i = 0; i < cryptlen; i++ )
                    {
                        String decryptedData = decryptParts[2 + i];
                        String intendedData = dataToCrypt[i];
                        if ( decryptedData.equals( intendedData ) )
                        {
                            result = true;
                        }
                        else
                        {
                            String error = new StringBuilder().append( "CSRF Token data does not match. Excepted: " )
                                .append( intendedData ).append( " but received: " ).append( decryptedData ).toString();

                            this.handler.handleValidationError( error );

                            result = false;

                            // if any fails, quit immediately
                            break;
                        }
                    }
                }
                else
                {
                    result = true;
                }
            }
        }
        catch ( Exception e )
        {
            String error = new StringBuilder().append( "Could not validate token " ).append( tokenString )
                .append( " for session " ).append( sessionID ).append( " due to exception: " ).append( e.getMessage() )
                .toString();

            this.handler.handleFatalException( error, e );
        }

        return result;
    }

    /**
     * encrypts or decrypts using AES/GCM and the given values
     *
     * @param key the key to use with *crypting
     * @param iv the iv to use when *crypting
     * @param textBytes the encrypted value to be decrypted OR the plaintext to be encrypted
     * @param mode either {@link Cipher#ENCRYPT_MODE} or {@link Cipher#DECRYPT_MODE}
     * @return the encrypted or decrypted value, depending on the given mode
     * @throws NoSuchAlgorithmException if the underlying code throws this exception
     * @throws NoSuchPaddingException if the underlying code throws this exception
     * @throws InvalidKeyException if the underlying code throws this exception
     * @throws InvalidAlgorithmParameterException if the underlying code throws this exception
     * @throws IllegalBlockSizeException if the underlying code throws this exception
     * @throws BadPaddingException if the underlying code throws this exception
     * @throws UnsupportedEncodingException if the underlying code throws this exception
     */
    private byte[] crypt( String key, String iv, byte[] textBytes, int mode )
        throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
        InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException
    {
        byte[] cryptedValue = null;
        Cipher cipher = Cipher.getInstance( "AES/GCM/NoPadding" );
        SecretKeySpec keyspec = new SecretKeySpec( key.getBytes( "UTF-8" ), 0, KEY_SIZE, "AES" );
        GCMParameterSpec gcmspec = new GCMParameterSpec( GCM_TAG_BITS, iv.getBytes( "UTF-8" ), 0, PARAMETER_SPEC_SIZE );
        cipher.init( mode, keyspec, gcmspec );
        cryptedValue = cipher.doFinal( textBytes );
        return cryptedValue;
    }

    /**
     * Return the current time for this application, in milliseconds. This method is exposed to subclasses as system
     * clocks may vary in multinode cloud environments that may span normal datetimes.
     * 
     * @return the current time in milliseconds
     */
    protected long getCurrentTime()
    {
        return System.currentTimeMillis();
    }

}

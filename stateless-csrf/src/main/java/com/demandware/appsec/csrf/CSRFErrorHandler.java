/*
 * Copyright 2016 Demandware Inc. Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions and limitations under the
 * License.
 */
package com.demandware.appsec.csrf;

/**
 * A Handler to be used in conjunction with the {@linkplain CSRFTokenManager}. The handler allows special configuration
 * to handle error/exception cases. It is recommended that implementors create a {@linkplain CSRFErrorHandler} that
 * utilizes their logging mechanisms for their application
 * 
 * @author Chris Smith
 */
public abstract class CSRFErrorHandler
{
    /**
     * Called when a CSRF Token cannot be validated for some reason
     * 
     * @param message the reason the token is invalid
     */
    public abstract void handleValidationError( String message );

    /**
     * Called when input to a CSRF function does not meet the required criteria for that function
     * 
     * @param message the reason this error was thrown
     */
    public abstract void handleInternalError( String message );

    /**
     * Called when a function encounters an exception it cannot recover from
     * 
     * @param message the current state of the function when the exception was thrown
     * @param e the exception thrown
     */
    public abstract void handleFatalException( String message, Exception e );
}

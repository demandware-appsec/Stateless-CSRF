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
 * A default implementation of {@linkplain CSRFErrorHandler} that simply dumps the passed data to the system error log
 * 
 * @author Chris Smith
 */
public class DefaultCSRFErrorHandler
    implements CSRFErrorHandler
{

    public void handleValidationError( String message )
    {
        System.err.println( message );
    }

    public void handleInternalError( String message )
    {
        System.err.println( message );
    }

    public void handleFatalException( String message, Exception e )
    {
        throw new SecurityException( message, e );
    }

}

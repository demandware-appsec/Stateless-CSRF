# Examples

## Standard Use Case Examples

### Inserting a Token Manually
```jsp
<form ...>
	...
	<input type="hidden" name="<%=csrfTokenManager.getCSRFTokenName()%>" value="<%=csrfTokenManager.generateToken(session.getId()%>"/>
	...
</form>
```

### Validating a Token
```java
public class CSRFFilter 
	implements Filter 
{
	...
	@Override
	public void doFilter( ServletRequest request, ServletResponse response, FilterChain chain ) 
		throws IOException, ServletException 
	{
		...
		if( shouldCSRFProtect ) // ensure through some means that this request *should* be protected
		{
			String sessionId = ( ( HttpServletRequest ) request ).getSession().getId();
			String token = ( ( HttpServletRequest ) request ).getParameterValue( csrfTokenManager.getCSRFTokenName() );
			csrfTokenManager.validateCSRFToken( token, sessionId );
		}
		...
	}
	...
}
```

## Using a custom CSRFErrorHandler
```java
public class LoggingCSRFErrorHandler
    extends CSRFErrorHandler
{
    private final Logger logger;

    private final Logger securityLogger;

    public LoggingCSRFErrorHandler( Logger logger, Logger securityLogger )
    {
        this.logger = logger;
        this.securityLogger = securityLogger;
    }

    @Override
    public void handleValidationError( String message )
    {
        this.securityLogger.error( "Vulnerability Detected: " + message );
    }

    @Override
    public void handleInternalError( String message )
    {
        this.logger.error( message );
    }

    @Override
    public void handleFatalException( String message, Exception e )
    {
        this.logger.fatal( message, e );
        throw new RuntimeException( message, e );
    }
}
```

# Stateless CSRF Token Management

## Documentation
[Stateless CSRF Token Management Documentation](http://demandware-appsec.github.io/Stateless-CSRF/javadoc/)

## Goal
Provide a Cross Site Request Forgery (CSRF) defense system that adds no state requirements. This implementation prioritizes speed via statelessness as each CSRF Token generated can not only be checked quickly when received but also be checked by any application server in a cluster as it does not rely on any in-memory storage. This implementation differs from the [OWASP CSRFGuard](https://github.com/esheri3/OWASP-CSRFGuard) project by neither requiring any particular setup such as maintaining session attributes in single node environments, nor saving the tokens between requests. This should be treated as core functionality upon which particular application logic may be built.

## Installation

Clone this repository, then run 
```
mvn -f stateless-csrf/pom.xml install
```
and look in stateless-csrf/target for the sources and jar file.

[JDK8 Prebuilt Jars](https://github.com/demandware-appsec/Stateless-CSRF/tree/gh-pages/jar)

## Design
### Background
To understand the design, first we must understand the attack this library defends against. 

Cross Site Request Forgery occurs under these circumstances: 
* A victim is logged into a particular website such as bank.com 
* An attacker creates a link that makes a request against bank.com to transfer funds
* The victim is tricked into clicking this link and making the request against bank.com
* The user's browser automatically sends the request along with all session information for bank.com
* The website validates that the request has the user's session, and executes the transfer

One strong prevention of this attack is to use a Synchronizer Token. This works so:
* A victim is logged into a particular website such as bank.com 
* An attacker creates a link that makes a request against bank.com to transfer funds
* The victim is tricked into clicking this link and making the request against bank.com
* The user's browser automatically sends the request along with all session information for bank.com
* The website validates that the request has the user's session, **and knows that this is a protected request**, so it also looks for an anti-csrf token, but doesn't find one, so the request fails
 
The first question is obvious: How does the token normally get into the good request? For each request that must be protected, the developers who designed the website added the token into the link that executes the request on bank.com. 

The next question usually is this: Why doesn't the attacker just steal a token and use that to trick the user? The answer is that the attacker is 100% allowed to do this and if he is able to steal the token, no anti-CSRF system will succeed. However, the only way to steal this token is to use some other kind of attack, such as [Cross Site Scripting](https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)) or a [Man in the Middle Attack](https://www.owasp.org/index.php/Man-in-the-middle_attack). These can be prevented with other counter-measures and so are out of scope for CSRF protections.

### Library Design
This library is designed to be stateless, or at least not add any new stateful information. It does this by utilizing the request's Session ID and encrypting it with a strong modern crypto suite. This ensures that it is nearly impossible to accidentally guess a good anti-CSRF token. 

The system generates tokens in this way:
* Given a Session ID of at least 16 bytes - **sessionID**
* Generate a random 8 byte -> 16 Hex character string - **tokenID**
* Generate a timestamp of this moment, in milliseconds - **timestamp**
* Create the text to be encrypted - **sessionID** + "|" + **timestamp** = **cryptText**
* Then, encrypt the **cryptText** using the first 16 bytes of the **sessionID** as the key and the 16 bytes of the **tokenID** as Initialization Vector - **encryptedValue**
* Hex encode the **encryptedValue** to produace the **tokenString**
* Finally, create the **CSRFToken** itself by doing **tokenID** + "|" + **tokenString**

To validate:
* The library needs the incoming **CSRFToken** and the **sessionID**
* First split the **CSRFToken** on the "|" character into **tokenID** and **tokenString**
* Generate a timestamp of this moment, in milliseconds - **timestamp**
* Hex decode the **tokenString** to the **encryptedValue**
* Decrypt the **encryptedValue** using the first 16 bytes of the **sessionID** as key and the **tokenID** as Initialization Vector - **cryptText**
* Split the **cryptText** into the **incomingSessionID** and **incomingTimestamp**
* Verify that the **incomingSessionID** equals the **sessionID** (all bytes, not just the first 16)
* Verify that the **incomingTimestamp** is within an expiration period of **timestamp**
* Should any step fail in this process, the token is invalid, should all steps pass verificaiton, the token is valid

In addition to this core functionality, a CSRFErrorHandler is used to pass messages about any errors that occur while generating/validating tokens. This CSRFErrorHandler has a Default implementation that simply logs messages to System.err, but it is strongly recommended that users of this system write their own Handler that logs messages to a security log, or throws exceptions.

### Example Usage
For code examples on using the library, please see [Examples](./EXAMPLES.md)

## Tests
Included is a set of JUnit tests that cover ~95% of instructions in the library.

## License
Copyright 2016  Demandware Inc, All Rights Reserved.

[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0.txt)

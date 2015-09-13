# Jwt easier - Json Web Token Utils

## How to use it?
### Basic Usage

**[ Jwt() ]**

```

	const Jwt = require('jwt-easier')

	let payload = {
		username: 'charliejuc',		
		exp: 1 * 60 * 1000 //Time or date in milliseconds
	}	

	let secret = 'My secret key to encrypt jwt'

	let options = {
		secret: secret,
		ttl: true 
		/*
			If ttl is true, payload.exp will be interpreted as the time 
			to live in milliseconds, otherwise payload.exp will be a 
			date to expire in milliseconds
		*/
	}

	let jwt = Jwt.create(payload, options)
	//eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImNoYXJsaWVqdWMiLCJleHAiOjYwMDAwfQ==.4mjVjW5zP6US4gfOyJKr5nmgA9bDMz5Hph23fG2RTgc=

	let decoded = Jwt.decode(payload, secret)	
	/*{ 
		header: { typ: 'JWT', alg: 'HS256' },		
  		payload: { username: 'charliejuc', exp: 1402129336809 } 
  	}*/

```

### Token Validation

```

	let payload = {
		username: 'charliejuc',		
		exp: 1441138682063
	}

	let secret = 'My secret key to encrypt jwt'

	let options = {
		secret: secret
	}

	let jwt = Jwt.create(payload, options)

	Jwt.isValid(jwt, secret) //It check whether jwt is a valid json web token
	//return true

	Jwt.isValid(jwt, 'other pass')
	//return false

	Jwt.isValid('Random string', secret)
	//return false

```

### Token Expired

**Valid only if you have defined 'exp' property in payload**

```
	
	let payload = {
		username: 'charliejuc',		
		exp: 1 * 60 * 1000
	}	

	let secret = 'My secret key to encrypt jwt'

	let options = {
		secret: secret,
		ttl: true 
	}

	let jwt = Jwt.create(payload, options)

	Jwt.expired(jwt, secret)
	//return true if time to live is over

```

### Get a Specific Property at Jwt

```

	let payload = {
		username: 'charliejuc',	
		other: 'another',
		exp: 1441138682063
	}

	let secret = 'My secret key to encrypt jwt'

	let options = {
		secret: secret
	}

	let jwt = Jwt.create(payload, options)

	let property = 'username'

	let fragment = 'payload' //Can be payload or header

	Jwt.resolveProperty(jwt, secret, property, fragment)
	//return charliejuc

	Jwt.resolveProperty(jwt, secret, 'other', fragment)
	//return another

```
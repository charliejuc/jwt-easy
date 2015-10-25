'use strict'

//jwt-easy
//Author: Juan Carlos Fernández || @Charliejuc
/*----------------------------*/

const hasher = require('simple-pass-hasher')

module.exports = function (errorCallback) {

	errorCallback = errorCallback || errorManager

	function createJwt (payload, options){
		if ( ! payload ) return errorCallback(new Error('Payload is required'))
		if ( ! options.secret ) return errorCallback(new Error('Secret is required'))
		if ( options.ttl && payload.exp ) {
			payload.exp += Date.now()
		}	

		const secret = options.secret

		let header = createHeader()
		payload = createPayload()

		let base64Sign = `${header}.${payload}`

		let sign = createSignature()

		function createHeader () {
			return stringToBase64(JSON.stringify({ 'typ': 'JWT', 'alg': 'HS256' }))
		}

		function createPayload () {
			let pay = isObject(payload) ? JSON.stringify(payload) : payload
			
			return stringToBase64(pay)
		}

		function createSignature () {
			let signHash = hasher({
				password: base64Sign,
				key: secret,
				algorithm: 'sha256',
				encoding: 'base64',
				hmac: true
			})

			return signHash.digest
		}

		function jwt () {
			return `${header}.${payload}.${sign}`
		}		

		return jwt()
	}

	function isValid (jwt, secret) {
		if ( ! jwt ) return errorCallback(new Error('Jwt is required'))
		if ( ! secret ) return errorCallback(new Error('Secret is required'))
		if ( ! jwt.split ) return false

		let split = jwt.split('.')

		if ( split.length !== 3 ) return false

		let validator = split[2]

		delete split[2]

		let args = split.join('.')

		args = args.slice(0, args.length - 1)

		let authHash = hasher({
							key: secret,
							algorithm: 'sha256',
							encoding: 'base64',
							hmac: true
						})

		return authHash.compare(args, validator)
	}

	function decodeJwt (jwt, secret) {
		if ( ! jwt ) return errorCallback(new Error('Jwt is required')	)
		if ( ! secret ) return errorCallback(new Error('Secret is required'))
		if ( ! isValid(jwt, secret) ) return errorCallback(new Error('Jwt validation failed'))

		let split = jwt.split('.')

		let header = new Buffer(split[0], 'base64').toString()
		let payload = new Buffer(split[1], 'base64').toString()

		header = JSON.parse(header)
		payload = JSON.parse(payload)

		return {
			header: header,
			payload: payload
		}
	}

	function jwtExpired (jwt, secret, property) {	
		if ( ! isValid(jwt, secret) ) return true	
		
		return isExpired(jwt, property)
	}

	function isExpired (jwt, property) {
		if ( ! jwt ) return errorCallback(new Error('Jwt is required'))

		property = property || 'exp'

		let exp = getProperty(jwt, property, 'payload')

		return exp <= Date.now()
	}

	function resolveJwtProperty (jwt, secret, property, fragment) {	
		if ( ! isValid(jwt, secret) ) return errorCallback(new Error('Jwt validation failed'))

		return getProperty(jwt, property, fragment)
	}

	function getProperty (jwt, property, fragment) {
		if ( ! jwt ) return errorCallback(new Error('Jwt is required')	)
		if ( ! property ) return errorCallback(new Error('Property is required'))
		fragment = getFragment(fragment)

		let piece = jwt.split('.')[fragment]

		let buf = new Buffer(piece, 'base64')

		let json = JSON.parse(buf.toString())

		if ( ! json[property] ) return errorCallback(new Error(`Property ${property}: not found in ${JSON.stringify(json)}`))

		return json[property]
	}

	function getFragment (fragment) {	
		let payload = 1,
		header = 0

		if ( ! fragment ) {
			return payload
		}

		if (fragment === 'payload') {
			return payload
		} else if (fragment === 'header') {
			return header
		}

		return errorCallback(new Error(`Fragment must be \'header' or \'payload': ${fragment} given`))
	}

	function isObject (bar) {
		let object = {}

		return isFoo(bar, object)
	}

	function isFoo (bar, comparator) {
		if (typeof(bar) != typeof(comparator)) return false

		return bar.constructor === comparator.constructor
	}

	function stringToBase64 (string) {
		return new Buffer(string).toString('base64')
	}

	function errorManager (err) {
		console.log(err.message)
	}   

	return {
		create: createJwt,
		decode: decodeJwt,
		isValid: isValid,
		expired: jwtExpired,
		resolveProperty: resolveJwtProperty
	}

}
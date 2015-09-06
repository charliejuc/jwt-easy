'use strict'

//jwt-easier
//Author: Juan Carlos Fernández || @Charliejuc
/*----------------------------*/

const hasher = require('simple-pass-hasher')

function createJwt (payload, secret){
	if ( ! payload ) throw new Error('Payload is required')
	if ( ! secret ) throw new Error('Secret is required')

	let headerJson = { 'typ': 'JWT', 'alg': 'HS256' }
	let payloadJson = payload

	let header = createHeader()
	payload = createPayload()

	let base64Sign = `${header}.${payload}`

	let sign = createSignature()

	function createHeader () {
		return stringToBase64(JSON.stringify(headerJson))
	}

	function createPayload () {
		return stringToBase64(JSON.stringify(payloadJson))
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
	if ( ! jwt ) throw new Error('Jwt is required')
	if ( ! secret ) throw new Error('Secret is required')
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
	if ( ! jwt ) throw new Error('Jwt is required')	
	if ( ! secret ) throw new Error('Secret is required')
	if ( ! isValid(jwt, secret) ) throw new Error('Jwt validation failed')

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
	if ( ! jwt ) throw new Error('Jwt is required')
	if ( ! isValid(jwt, secret) ) return true	
	property = property || 'exp'

	let exp = resolveJwtProperty(jwt, secret, property, 'payload')

	return exp <= Date.now()
}

function resolveJwtProperty (jwt, secret, property, fragment) {
	if ( ! jwt ) throw new Error('Jwt is required')
	if ( ! property ) throw new Error('Property is required')
	if ( ! isValid(jwt, secret) ) throw new Error('Jwt validation failed')
	fragment = getFragment(fragment)

	let piece = jwt.split('.')[fragment]

	let buf = new Buffer(piece, 'base64')

	let json = JSON.parse(buf.toString())

	if ( ! json[property] ) throw new Error(`Property ${property}: not found in ${JSON.stringify(json)}`)

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
	} else {
		throw new Error(`Fragment must be \'header' or \'payload': ${fragment} given`)
	}
}

function stringToBase64 (string) {
	return new Buffer(string).toString('base64')
}

module.exports =  {
	create: createJwt,
	decode: decodeJwt,
	isValid: isValid,
	expired: jwtExpired,
	resolveProperty: resolveJwtProperty
}
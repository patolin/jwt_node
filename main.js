const jose = require('jose');
const crypto = require('crypto');

const JWT_ISSUER = 'https://www.todomejora.org/'
const JWT_AUDIENCE = JWT_ISSUER + 'app/';
const JWT_EXPIRE = '8h'
const JWT_ALG = 'dir';
const JWT_ENCRYPTION = 'A256GCM';
const JWT_HEADER_ENCRYPTION = "HS256";
const SECRET_KEY = Buffer.from("62197fc8886bd3b739dd2cc8aa109d0be93acdea64c07b8908168b80daf1dc47", "hex"); // 256 bits => 64 characters hex

const SYMMETRIC_ENCRYPTION_ALGORITHM = 'aes-256-cbc';

function generateRandomHex(size) {
	const randomBytes = crypto.randomBytes(size);
	const hexString = randomBytes.toString('hex');
	return hexString;
  }

const generateEncryptedJwt = (subject, payload, secret) => {
	return new jose.EncryptJWT(payload)
		.setProtectedHeader({ alg: JWT_ALG, enc: JWT_ENCRYPTION })
		.setIssuedAt()
		.setSubject(subject)
		.setIssuer(JWT_ISSUER)
		.setAudience(JWT_AUDIENCE)
		.setExpirationTime(JWT_EXPIRE)
		.encrypt(secret);
};

const decryptJwt = async (jwt, secret) => {
	const options = {
		issuer: JWT_ISSUER,
		audience: JWT_AUDIENCE,
		contentEncryptionAlgorithms: [JWT_ENCRYPTION],
		keyManagementAlgorithms: [JWT_ALG],
	};
	return jose.jwtDecrypt(jwt, secret, options);
};

const signJwt = async (subject, payload, secret) => {
	return new jose.SignJWT(payload)
		.setProtectedHeader({ alg: JWT_HEADER_ENCRYPTION })
		.setSubject(subject)
		.setIssuedAt()
		.setIssuer(JWT_ISSUER)
		.setAudience(JWT_AUDIENCE)
		.setExpirationTime(JWT_EXPIRE)
		.sign(secret)
};

const verifyJwt = async (jwt, secret) => {
	return await jose.jwtVerify(jwt, secret, {
		issuer: JWT_ISSUER,
		audience: JWT_AUDIENCE,
		algorithms: [JWT_HEADER_ENCRYPTION],
	});
}

  function symmetricEncryptMessage(message, key) {
	const algorithm = SYMMETRIC_ENCRYPTION_ALGORITHM;
	const iv = crypto.randomBytes(16); // Initialization Vector
  
	const cipher = crypto.createCipheriv(algorithm, Buffer.from(key, 'hex'), iv);
	let encryptedMessage = cipher.update(message, 'utf-8', 'hex');
	encryptedMessage += cipher.final('hex');
	
	//console.log({ iv: iv.toString('hex'), encryptedMessage });
	return iv.toString('hex') + encryptedMessage;
  }

  function symmetricDecryptMessage(message, key) {
	const iv = message.toString().substring(0,32);
	const encryptedMessage = message.substring(32);
	console.log('desencriptando: ', iv, encryptedMessage);
	const algorithm = SYMMETRIC_ENCRYPTION_ALGORITHM;
  
	const decipher = crypto.createDecipheriv(algorithm, Buffer.from(key, 'hex'), Buffer.from(iv, 'hex'));
	let decryptedMessage = decipher.update(encryptedMessage, 'hex', 'utf-8');
	decryptedMessage += decipher.final('utf-8');
  
	return decryptedMessage;
  }

  async function validateKey(jwtToken, secret, key) {
	const decrypted = await decryptJwt(jwtToken, secret);
	return key===decrypted.payload.symmetric_key;
  }

async function main() {
	
	const secret = SECRET_KEY;
	const randomKey = generateRandomHex(32);
	const payload = {'symmetric_key': randomKey, 'user_id': 'U000001'};

	console.log('payload: ', payload);
	
	// generamos el token jwt
	const encryptedJwt = await generateEncryptedJwt("testsub", payload, secret);
	console.log('encrypted jwt: ', encryptedJwt)

	// obtenemos la llave simétrica
	const symmetricKey = payload["symmetric_key"];

	// encriptamos el mensaje
	const message = "esto es una prueba"
	const messageEncrypted = symmetricEncryptMessage(message, symmetricKey);
	console.log('symmetric encrypted message: ', messageEncrypted);

	// validamos la llave
	const validKey = await validateKey(encryptedJwt, secret, symmetricKey)
	if (validKey) {
		const messageDecrypted = symmetricDecryptMessage(messageEncrypted, symmetricKey);
		console.log('symmetric decripted message: ', messageDecrypted);
	} else {
		console.log('la llave simétrica no puede ser validada con jwt');
	}

	


	
	// const decrypted = await decryptJwt(encryptedJwt, secret);
	
	// console.log('decrypted jwt: ', decrypted);
	
	// const signedJwt = await signJwt("testsub", payload, secret);
	// const verifiedJwt = await verifyJwt(signedJwt, secret);

	// console.log('signed: ', signedJwt);
	
	//console.log({payload, secretString: secret.toString("base64"), secret, encryptedJwt, encryptedParts: encryptedJwt.split(".").map((p) => Buffer.from(p, "base64url").toString("utf8")).join("."), decrypted, signedJwt, signedParts: signedJwt.split(".").map((p) => Buffer.from(p, "base64url").toString("utf8")).join("."), verifiedJwt});

}

main();

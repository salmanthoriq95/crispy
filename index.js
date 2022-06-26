//@ts-check
"use strict";

// Import Native Crypto from nodeJs
const crypto = require("crypto");
const algorithm = "aes-256-cbc";

// Import Crypto-Js from npm
const CryptoJs = require("crypto-js");
const AES = require("crypto-js/aes");
let optionalConfig;
// import redis
// const Redis = require("../db.Interface/redis/queries/redis.queries");
// const redis = new Redis();
/**
 * Generate random string with value [A-Za-z0-9]
 * @see https://stackoverflow.com/questions/1349404/generate-random-string-characters-in-javascript
 * @param {number} length word length that will return
 * @returns {string} random string
 */
const generateRandomString = (length) => {
	let result = "";
	let characters =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	let charactersLength = characters.length;
	for (let i = 0; i < length; i++) {
		result += characters.charAt(Math.floor(Math.random() * charactersLength));
	}
	return result;
};

/**
 * encrypting string use crypto NodeJs native
 * @param {string} text
 * @returns {{iv: string, encryptedData: string, key: string}}
 */
const encryptCryptoNative = (text) => {
	// Generate random key
	const key = crypto.randomBytes(32);
	const iv = crypto.randomBytes(16);

	let cipher = crypto.createCipheriv(algorithm, Buffer.from(key), iv);
	let encrypted = cipher.update(text);
	encrypted = Buffer.concat([encrypted, cipher.final()]);
	return {
		iv: iv.toString("hex"),
		encryptedData: encrypted.toString("hex"),
		key: key.toString("hex"),
	};
};

/**
 * decrypring data using crypto NodeJs native
 * @param {{iv: string, encryptedData: string, key: string}} text
 * @returns {string}
 */
const decryptCryptoNative = (text) => {
	let iv = Buffer.from(text.iv, "hex");
	let key = Buffer.from(text.key, "hex");
	let encryptedText = Buffer.from(text.encryptedData, "hex");
	let decipher = crypto.createDecipheriv("aes-256-cbc", Buffer.from(key), iv);
	let decrypted = decipher.update(encryptedText);
	decrypted = Buffer.concat([decrypted, decipher.final()]);
	return decrypted.toString();
};

/**
 * encrypt message using crpto-js npm
 * @param {*} rawData
 * @returns {{data: string, key:string}}
 */
const encryptCryptoJs = (rawData, options) => {
	// generate random key
	const keyLength = options.keyLength ?? 10;
	const key = options.key ? options.key : generateRandomString(keyLength);

	// convert into string
	const data = JSON.stringify(rawData);

	// encrypt message
	const rawEncrypted = AES.encrypt(data, key).toString();

	// escape special character
	const encrypted = rawEncrypted
		.replace(/\+/g, "p1L2u3S")
		.replace(/\//g, "s1L2a3S4h")
		.replace(/=/g, "e1Q2u3A4l");

	return {
		data: encrypted,
		key,
	};
};

/**
 * decrypt data using crypto-js npm
 * @param {string} encrypedData
 * @param {string} key
 * @returns {string | boolean}
 */
const decrptCryptoJs = (encrypedData, key) => {
	// Decrypt data
	const dataCrypt = encrypedData
		.replace(/p1L2u3S/g, "+")
		.replace(/s1L2a3S4h/g, "/")
		.replace(/e1Q2u3A4l/g, "=");
	const decryptedData = AES.decrypt(dataCrypt, key);
	const data = decryptedData.toString(CryptoJs.enc.Utf8);

	if (!data || data === "") return false;

	return data;
};

/**
 * create new token
 * @param {string|number|Array<any>|object} plainText
 * @returns {{data: string, key: string}}
 */
const encrypt = (plainText) => {
	// first encrypt using native nodeJs
	const firstEncryption = encryptCryptoNative(JSON.stringify(plainText));

	// second encryption use crypto-js
	const encryptedData = encryptCryptoJs(
		JSON.stringify(firstEncryption),
		optionalConfig
	);

	return encryptedData;
};

/**
 * decrypt the token
 * @param {string} token
 * @param {string} key
 * @returns {*}
 */
const decrypt = (token, key) => {
	// decrypt use crypto-js
	const firstDecrypt = decrptCryptoJs(token, key);
	const firstDecrptedData = JSON.parse(JSON.parse(firstDecrypt.toString()));

	// decrypt using native nodeJS
	const decryptData = decryptCryptoNative(firstDecrptedData);

	return decryptData;
};

/**
 * main function
 * @param {object} options
 * @param {string} [options.key]
 * @param {number} [options.length]
 * @returns {*}
 */
const main = (options) => {
	optionalConfig = options;
	return {
		encrypt: () => {},
		decrypt: () => {},
	};
};

module.exports = main;
module.exports.default = main;

const crypto = require("crypto");

// Create a module for utility functions
// This module provides various utility functions for the application.

/**
 * Returns a 32-bit integer hash of the input string, using SHA-256.
 * Equivalent to the .NET code: BitConverter.ToInt32(sha256, 0)
 */
function GetWebCode(input) {
	// SHA256 hash as a Buffer
	const hash = crypto
		.createHash("sha256")
		.update(input.toLowerCase(), "utf8")
		.digest();

	// Read first 4 bytes as a signed 32-bit integer (little-endian, like BitConverter)
	return hash.readInt32LE(0);
}

module.exports = { GetWebCode };

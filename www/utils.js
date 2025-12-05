// Create a module for utility functions
// This module provides various utility functions for the application.

/**
 * Returns a 32-bit integer hash of the input string, using SHA-256.
 * Equivalent to the .NET code: BitConverter.ToInt32(sha256, 0)
 */
export async function GetWebCode(input) {
	// Convert input string to lowercase and encode as UTF-8
	const encoder = new TextEncoder();
	const data = encoder.encode(input.toLowerCase());

	// SHA256 hash using Web Crypto API
	const hashBuffer = await crypto.subtle.digest("SHA-256", data);

	// Convert to DataView to read as 32-bit integer
	const view = new DataView(hashBuffer);

	// Read first 4 bytes as a signed 32-bit integer (little-endian, like BitConverter)
	return view.getInt32(0, true);
}

export function CallRESTAPI(
	endpoint,
	method,
	options,
	okCallback,
	errorCallback,
	exceptionCallback,
) {
	let prepared_options = {
		headers: {
			"Content-Type": "application/json",
		},
		body: JSON.stringify(options),
	}

	// Merge method with options
	const requestOptions = {
		method: method,
		...prepared_options,
	};

	const request = new Request(endpoint, requestOptions);
	fetch(request)
		.then((response) => {
			if (!response.ok) {
				errorCallback(response);
			} else {
				okCallback(response);
			}
		})
		.catch((error) => {
			exceptionCallback(error);
		});
}

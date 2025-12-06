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

export async function CallRESTAPI(endpoint, method = "GET", options = {}) {
	const requestOptions = {
		method,
		headers: options.headers || { "Content-Type": "application/json" },
	};

	if (options.body !== undefined) {
		requestOptions.body = typeof options.body === "string" ? options.body : JSON.stringify(options.body);
	}

	const response = await fetch(endpoint, requestOptions);
	if (!response.ok) {
		const text = await response.text().catch(() => null);
		const err = new Error("HTTP error " + response.status);
		err.status = response.status;
		err.body = text;
		throw err;
	}

	// Try to parse JSON, fall back to text/null
	const ct = response.headers.get("content-type") || "";
	if (ct.includes("application/json")) return response.json();
	return response.text().catch(() => null);
}

export function createCookie(name, value, days, opts = {}) {
	let parts = [];
	if (days) {
		const date = new Date();
		date.setTime(date.getTime() + days * 24 * 60 * 60 * 1000);
		parts.push("expires=" + date.toUTCString());
	}
	parts.push("path=/");
	if (opts.sameSite) parts.push("SameSite=" + opts.sameSite);
	if (opts.secure) parts.push("Secure");

	let cookieStr = name + "=" + encodeURIComponent(value || "");
	if (parts.length) cookieStr += "; " + parts.join("; ");
	document.cookie = cookieStr;
}

export function readCookie(name) {
	const nameEQ = name + "=";
	const ca = document.cookie.split(";");
	for (let i = 0; i < ca.length; i++) {
		let c = ca[i];
		while (c.charAt(0) === " ") c = c.substring(1, c.length);
		if (c.indexOf(nameEQ) === 0)
			return c.substring(nameEQ.length, c.length);
	}
	return null;
}

export function eraseCookie(name) {
	document.cookie = name + "=; Max-Age=-99999999;";
}
# Code Citations

## License: MIT

https://github.com/etcherfx/Phosphur/blob/e294e068918d4f0636f93feb9c961e00b7ed7e3e/src/index.js

```
server.address();

	// by default we are listening on 0.0.0.0 (every interface)
	// we just need to list a few
	console.log("Listening on:");
	console.log(`\thttp://localhost:${address.port}`);
	console.log(`\thttp://${hostname()}:${address.port}`);
	console.log(
		`\thttp://${
			address.family === "IPv6" ? `[${address.address}]` : address.address
		}:${address.port}`
	);
});

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

function shutdown() {
	console.log("SIGTERM signal received: closing HTTP server")
```

## License: unknown

https://github.com/maxiz1225/the-simple-unblocker-public/blob/e56157b24a2c6213e9b4cca54c8a481bf52c802f/src/index.js

```
server.address();

	// by default we are listening on 0.0.0.0 (every interface)
	// we just need to list a few
	console.log("Listening on:");
	console.log(`\thttp://localhost:${address.port}`);
	console.log(`\thttp://${hostname()}:${address.port}`);
	console.log(
		`\thttp://${
			address.family === "IPv6" ? `[${address.address}]` : address.address
		}:${address.port}`
	);
});

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

function shutdown() {
	console.log("SIGTERM signal received: closing HTTP server")
```

## License: unknown

https://github.com/CLOXKEDMASKED/cloxkedmasked.github.io/blob/2829f6f7e6d3ba92cc6b4c5a3b0a9ebb36e41e12/src/index.js

```
server.address();

	// by default we are listening on 0.0.0.0 (every interface)
	// we just need to list a few
	console.log("Listening on:");
	console.log(`\thttp://localhost:${address.port}`);
	console.log(`\thttp://${hostname()}:${address.port}`);
	console.log(
		`\thttp://${
			address.family === "IPv6" ? `[${address.address}]` : address.address
		}:${address.port}`
	);
});

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

function shutdown() {
	console.log("SIGTERM signal received: closing HTTP server")
```

## License: unknown

https://github.com/workskins/workskins/blob/94f98b3c8edcdc0c89617227a10953ffbb3a2780/public/index.css

```
-address:focus {
	border: 1px solid rgba(253, 253, 253, 0.514);
	border-radius: 6px;
}

.credit {
	border-radius: 10px;
	padding: 10px;
	display: block;
	border: #fff 1px solid;
	color: #fff;
	display: flex;
	flex-wrap: wrap;
	margin-bottom: 15px;
}

.credit label {
	margin-left: auto;
	margin-right: 15px;
}

.credit a,
.credit label {
	color: white;
	text-decoration: underline;
	text-align: right;
}

.credit pre {
	display: none;
	width: 100%;
}

.credit label::after {
	content: "show license";
	cursor: pointer;
}

.credit input:checked + label::after {
	content: "hide license";
}

.credit input:checked ~ pre {
```

## License: unknown

https://github.com/Teerths/BRO-WORK/blob/0ff9acfe9648dcafe3c235e4e9d6508c44d2fe69/index.css

```
-address:focus {
	border: 1px solid rgba(253, 253, 253, 0.514);
	border-radius: 6px;
}

.credit {
	border-radius: 10px;
	padding: 10px;
	display: block;
	border: #fff 1px solid;
	color: #fff;
	display: flex;
	flex-wrap: wrap;
	margin-bottom: 15px;
}

.credit label {
	margin-left: auto;
	margin-right: 15px;
}

.credit a,
.credit label {
	color: white;
	text-decoration: underline;
	text-align: right;
}

.credit pre {
	display: none;
	width: 100%;
}

.credit label::after {
	content: "show license";
	cursor: pointer;
}

.credit input:checked + label::after {
	content: "hide license";
}

.credit input:checked ~ pre {
```

## License: Apache-2.0

https://github.com/prjamming/Terbium/blob/37cded65b93ddf8c92b6d007a2581b634b802798/static/bruhprox/index.css

```
-address:focus {
	border: 1px solid rgba(253, 253, 253, 0.514);
	border-radius: 6px;
}

.credit {
	border-radius: 10px;
	padding: 10px;
	display: block;
	border: #fff 1px solid;
	color: #fff;
	display: flex;
	flex-wrap: wrap;
	margin-bottom: 15px;
}

.credit label {
	margin-left: auto;
	margin-right: 15px;
}

.credit a,
.credit label {
	color: white;
	text-decoration: underline;
	text-align: right;
}

.credit pre {
	display: none;
	width: 100%;
}

.credit label::after {
	content: "show license";
	cursor: pointer;
}

.credit input:checked + label::after {
	content: "hide license";
}

.credit input:checked ~ pre {
```

## License: unknown

https://github.com/maxiz1225/the-simple-unblocker-public/blob/e56157b24a2c6213e9b4cca54c8a481bf52c802f/public/register-sw.js

```
/**
 * List of hostnames that are allowed to run serviceworkers on http://
 */
const swAllowedHostnames = ["localhost", "127.0.0.1"];

/**
 * Global util
 * Used in 404.html and index.html
 */
async function registerSW() {
	if (!navigator.serviceWorker) {
		if (
			location.protocol !== "https:" &&
			!swAllowedHostnames.includes(location.hostname)
		)
			throw new Error("Service workers cannot be registered without https.");

		throw new Error("Your browser doesn't support service workers.");
	}

	await navigator.serviceWorker.register(
```

## License: MIT

https://github.com/titaniumnetwork-dev/Ultraviolet-Static/blob/c2492602685e510ab7c6eea9548ffb4c5fdee1cd/public/register-sw.js

```
/**
 * List of hostnames that are allowed to run serviceworkers on http://
 */
const swAllowedHostnames = ["localhost", "127.0.0.1"];

/**
 * Global util
 * Used in 404.html and index.html
 */
async function registerSW() {
	if (!navigator.serviceWorker) {
		if (
			location.protocol !== "https:" &&
			!swAllowedHostnames.includes(location.hostname)
		)
			throw new Error("Service workers cannot be registered without https.");

		throw new Error("Your browser doesn't support service workers.");
	}

	await navigator.serviceWorker.register(
```

## License: unknown

https://github.com/maxiz1225/the-simple-unblocker-public/blob/e56157b24a2c6213e9b4cca54c8a481bf52c802f/public/search.js

```
/**
 *
 * @param {string} input
 * @param {string} template Template for a search query.
 * @returns {string} Fully qualified URL
 */
function search(input, template) {
	try {
		// input is a valid URL:
		// eg: https://example.com, https://example.com/test?q=param
		return new URL(input).toString();
	} catch (err) {
		// input was not a valid URL
	}

	try {
		// input is a valid URL when http:// is added to the start:
		// eg: example.com, https://example.com/test?q=param
		const url = new URL(`http://${input}`);
		// only if the hostname has a TLD/subdomain
		if (url.hostname.includes(".")) return url.toString();
	} catch (err) {
		// input was not valid URL
	}

	// input may have been a valid URL, however the hostname was invalid

	// Attempts to convert the input to a fully qualified URL have failed
	// Treat the input as a search query
	return template.replace("%s", encodeURIComponent(input));
}
```

## License: unknown

https://github.com/maxiz1225/the-simple-unblocker-public/blob/e56157b24a2c6213e9b4cca54c8a481bf52c802f/src/index.js

```
server.address();

	// by default we are listening on 0.0.0.0 (every interface)
	// we just need to list a few
	console.log("Listening on:");
	console.log(`\thttp://localhost:${address.port}`);
	console.log(`\thttp://${hostname()}:${address.port}`);
	console.log(
		`\thttp://${
			address.family === "IPv6" ? `[${address.address}]` : address.address
		}:${address.port}`
	);
});

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

function shutdown() {
	console.log("SIGTERM signal received: closing HTTP server")
```

## License: unknown

https://github.com/CLOXKEDMASKED/cloxkedmasked.github.io/blob/2829f6f7e6d3ba92cc6b4c5a3b0a9ebb36e41e12/src/index.js

```
server.address();

	// by default we are listening on 0.0.0.0 (every interface)
	// we just need to list a few
	console.log("Listening on:");
	console.log(`\thttp://localhost:${address.port}`);
	console.log(`\thttp://${hostname()}:${address.port}`);
	console.log(
		`\thttp://${
			address.family === "IPv6" ? `[${address.address}]` : address.address
		}:${address.port}`
	);
});

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

function shutdown() {
	console.log("SIGTERM signal received: closing HTTP server")
```

## License: MIT

https://github.com/etcherfx/Phosphur/blob/e294e068918d4f0636f93feb9c961e00b7ed7e3e/src/index.js

```
server.address();

	// by default we are listening on 0.0.0.0 (every interface)
	// we just need to list a few
	console.log("Listening on:");
	console.log(`\thttp://localhost:${address.port}`);
	console.log(`\thttp://${hostname()}:${address.port}`);
	console.log(
		`\thttp://${
			address.family === "IPv6" ? `[${address.address}]` : address.address
		}:${address.port}`
	);
});

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

function shutdown() {
	console.log("SIGTERM signal received: closing HTTP server")
```

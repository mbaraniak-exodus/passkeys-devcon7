console.log("frida-dump");

Java.perform(() =>{

	const OpenSSLECPrivateKey = Java.use("com.google.android.gms.org.conscrypt.OpenSSLECPrivateKey");

	// Signature
		var signature = Java.use("java.security.Signature");
		signature.getInstance.overload('java.lang.String').implementation = function (var0) {
			console.log("[*] Signature.getInstance called with algorithm: " + var0 + "\n");
			return this.getInstance(var0);
		};

		signature.initSign.overload("java.security.PrivateKey").implementation = function(privateKey) {
			console.log("Signature key " + privateKey.$className);
			if (privateKey.$className == "com.google.android.gms.org.conscrypt.OpenSSLECPrivateKey") {
				var privateKey2 = Java.cast(privateKey, OpenSSLECPrivateKey);
				console.log(privateKey2.getS());
			}
			return signature.initSign.overload("java.security.PrivateKey").call(this, privateKey);
		};

});


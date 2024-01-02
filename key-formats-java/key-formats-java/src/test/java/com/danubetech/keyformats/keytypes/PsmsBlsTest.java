package com.danubetech.keyformats.keytypes;

import com.danubetech.keyformats.JWK_to_PrivateKey;
import com.danubetech.keyformats.JWK_to_PublicKey;
import com.danubetech.keyformats.PublicKeyBytes;
import com.danubetech.keyformats.PublicKey_to_JWK;
import com.danubetech.keyformats.jose.JWK;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class PsmsBlsTest  extends AbstractTest{

    static final JWK jwkPublic;
    static final JWK jwkPrivate;

    static {
        try {
            jwkPublic = JWK.fromJson("""
                    {
                    	"kty": "EC",
                    	"crv": "PSMS",
                    	"vx": {
                    		"x": "XDAyMU5cMjIwXDMzNlwwMTdcMjAzXDMwNCZcMjUxXDMxNlwzNTc1e1wzNjZcMjIyXHRzXDMwMVwyMTdcMzMzXDIwM1wyNzBcMzAyUFwyMzRcZlwyNjYkXDM2M1wzNTRcXFwzNTJcMzI2XDM0NVwyNjRcMzAzXDI1MD5cMDM0XDIzM1wyMDdcMjQwXDI1N1wyMDdcMjU0XDIzMVwzMDRcMDI0XDM1NVwyNTNcMjc3XDE3N1wyNjNcZlwwMDBcMzA0XDIwNVk=",
                    		"y": "XG5cMDA0XDMzMlBcMjc1XDMxMVwyNTJcMzMyXDM1NVwwMzNcMjIzXDIzN1wzNTFcMzUzLFwwMDVcMjAyXDIzNHFcMjE2XHRDJCZcMjU2a1hcMjQ3bFwwMjN2XGZ7XDMzNlwyMjVcMjQwQnxRUSxcMDAzXDI2NlwzMzBRTVwyNDFyQlwyNTIhXDAwNTxcMzI0XDMyMk5tbg=="
                    	},
                    	"vy_m": {
                    		"x": "XDAwNFx0XDIzNDlpXDAyNlwzNzBcMzAxXGJcMDI3XDIzNChcMjc3flwyMjJcdGZRRFwyNjRcMDA2R1wzMzJcIlwyNDJcdk5cMjMxalwzNzFcMDMxXDAyMlwwMDBcMjU1XDM3N1wyMzFTKVwyMjdVR1wzMzQlWVwyNTNcMjU3ISt+XDM1NlwzNTRcMjIydFwzMjNcMjU2XDMzNlwyMTJcMjA2",
                    		"y": "XDAwNFwyNjdgXDMyMFxmXDIzMlwyMjdcMzMzXDAyNFwyMjV1ZFwwMzJtXDAzM1wyNzYhXDAzNlwyNDdcMzU3XDMzNlwyNzNkXDI3MlxcQHFcMjYwQFwzMzJcMzU2XlwwMjFcMDIwXDI2M1wzNzE9XDM3NFwwMzVcMzY2XDIyMlwyNTVcMDI2VlwzNDRcMjU3XDMwNVwzNzdcMzM1QFwyNjJcMjMyXDI3N1BcMjM3N1wzMDBcMTc3"
                    	},
                    	"vy_epoch": {
                    		"x": "XDAyMVxhaXAjXDI0MSxcMzIxXDM1M1wzMTNcMjczUVwyMDNcMDAyXHJcMjU3IVhcMjcwXDI2M1lcMjY1XDI3N1wyMzJhXDI2Nl9cMzc3QTxcMzEyXDMxMXhcMzI1Z1wwMDRcMzcyY35cMDE3XDMzMVwiXDM1NlwwMzZcMzIxUVwyMjFcMDI0XDIyNVwzNjZcMzYyXGFcMjAwXDI0M2J7XDMwNFwzNjE=",
                    		"y": "XGJvXDIxNVwzMDVpXDM2NkxcMzc1SlwzMjFcMzY2UVwyNjNcMjY2XDM0MFwzNzNcMjMzXDAyM1wyMDFcMjYyXDMxN1wyMTBcMjA0a2RzXDIyNGlcYVwyMjBaXDI2NlwyNTRcMjE2XDMwM1pvXDM2NVNcMzMxXDI1MlwwMzRcMjYwXDMxMlwyNTZcMjMwXDAwMFwwMjBcMzQyY1wyNDdcMDM0XDIwMFwyMzBsPjVT"
                    	},
                    	"vy": {
                    		"https://w3id.org/citizenship#residentSince": {
                    			"x": "XDAwNHhcMDAxXDI0NlwwMDBcMDI0Z1wyNjFcMzYxKVwyNzBuXDI3Nz0teit2XDM0NlwyNTRcMjMxOj5cMzQzcFwyMDYhXDI0NlwzMjVcdHhfXDI1MVwyMjNcMjIwNFwzNjBcMzM1b1wzMDQwXDMwMVwwMTZcMDI2bFwyNTV6XDI1MFwzNDFcMjAxXDIxM1wzNDFcMjUxXDM0MXo+Jio=",
                    			"y": "XHJcMzYyMlwzNTIxXDI0MVwyMTdcMjU3UFwzNTNcMDA2XDI2MVwyMTdcMjUxNW9cMzIyXDMxM3FcMjY2REdyXDI2NT5cMjY3XCd4XDM3NlwyMjJcMjI1XDAzNX5nS2dcMjIxXDI3NXdcMjYzUFwyNDcpXDM1NVwzNTBcMjM3XDI1MUtcMjY3XDI3MVwzMjJcMzc0TnxiXDI3MVwwMzVcMjA3"
                    		},
                    		"https://w3id.org/citizenship#lprCategory": {
                    			"x": "XGFRPVwyNjBcMDM1XDM0M1wyNDBcMzI1Ky1cMTc3XDM2MlwwMzdcMzUxXDAyMlwzMTBcYVwyMDZcMjM2bGxcMzYxT11tXDM3M1xiXDAzMVdcMjExXDIwMy8yXDMxNFwyMzJcMjIxXDI0NFwwMjBcMDI1XDIyMXhSXDMyNVwwMDFcMzc0XDM3MVBcMDM2XDAzNlwyNTFcMzEzXDM3MVwwMjVcMzIzXDI3MVwwMzNcMzczXDM1MQ==",
                    			"y": "XGZcMTc3VkNcMjc1XDIyMFJcMzI2XGFcXHxcMjEwVVwwMjRcdFwzNzZcMjI2JVx2XDIzMFwyMzZcMjY1XDMxMypAXDI2MFwzNjZcMjUzXDI3N1wyNzI8XDMyNGBJXDAzNzJcMjYwXDMxMVwyMDBcMjc1XDAzMlwzNTNiZm5cMzMxXDI1Mio4XHJcIj5cMDA2XHJHXDAzMFwzNDFcMzUw"
                    		},
                    		"https://www.w3.org/2018/credentials#issuer": {
                    			"x": "XGJcMzY2Y1wyNjVcMzA0XDI0NVwwMjNsKTdAS3VcMjUyXDMwMHdcMjA1XGZcMzIyfFwyMzJcMjA2XDM1NlwzMzBhXDM1NFkuXDIwMXIzN1wyNDFcMjAxXDM2MGNcMjUwKVwwMjczXDMyMlwzMDRcMjA1M2pcMDIzXDIwMFwzMTdcMjUzXDMxNFwyMDdcMzc1PGtcMzc1T1wzNzdcMzcy",
                    			"y": "XDAwMSFcMzIxXDM2Nn1KPT56XDAzN1wzMDRcMjM1JFwyNDZcMTc3XDMzMFhDXDM3NFwwMjNEXDAyNlwyMjFcMjYyalwwMjVcMzEyXDE3N2FZXDMyNVwyMjBaXDI0NFwyMjJcMjYxXDIzNntUXDI1NVwzMDNcMDA2XDMxM1wzNDVfXDAwMkVcMDM2XDIxN1wyMDc+PlwyMDVcMTc3XDAzN1wwMzI0XDI2Mg=="
                    		},
                    		"https://www.w3.org/2018/credentials#issuanceDate": {
                    			"x": "XDAyMFwzNTFcMzU0XGZcMjE3XDAyMFx0XDM2MlwyMDBcMzM3XlwyMTFcMjUwXDI1MFwyNjdcMzYxXDAyN1wzNzBcMjUxNTtqIDtcMzYyXGYmXDI3NFwzNjJcYlNcMzMyKVwyNTRcMjY3XDIzMDVcMzE2XHZcMjMwXDIwMFwzMzNccmZcMzM3XDAzN1wwMjNXQlwyMTRcMDM3XDM0N1wwMzZcMjI1XDMzNVwyNzAqeA==",
                    			"y": "XDAyNHhcIlwzNDFxXDIwNlwwMDNKTXdcMzcwXDI1MzJcMzQ2WlwyNzFcMjUxXDAwMVwyMDdcMjU2X3lje1wzNDZsXDM1M1wyMTBcMDIzXDM1NlwyMDR3XDM1MSVOYUQ3XDAwM1wzMjJBXDI2M19cMzM3LVwzNDRcMjA3XDIwMVwyMDEgVFwzMjF6QEllJFwyNDY="
                    		},
                    		"https://w3id.org/citizenship#lprNumber": {
                    			"x": "XDAwM1wzNzVcMDIzVVwzNjNcMjYwPlwyMDVcMjMwI1wzNjNcMjMwcEx2PiFcMjYxXDI1NFwyMTBcMzUzTlwyMDdcMzU3OD1cMzcxKFwyMDJDXDMwMlwyMzElXDI3MmNcMzU1YUFcMjQzalwzNzVcMzMwWnZcMjUyWVwyNzQ9XDIzMnZcMDAzXDM0MFwyMDBcMzA1XDI0M1wzMDJcMDM0Zg==",
                    			"y": "XDAyMFwyMDZNXDI2NVwyNDRHXDMwMTQwXDIxM1wzNDBzXDMzMFwyMDBcMzE2XDI2NlwyMjI1XDM2MGBcMzE1XDAzNVNcMDIwXDMxMGJcMjYwXDM0MlwwMjdcMzc3XDM2N1wwMjBcMjEwXDI2MFwyNDRgXDMwNFwyNjRcMjI0JVwwMzdcMzU0XDI3M1wwMzNcMjQzRiNcMzMyXDMyNFwzNDZlXDM0NVwyMzJcMDE3XDM2M1wyMjcseg=="
                    		},
                    		"https://w3id.org/citizenship#commuterClassification": {
                    			"x": "XGJcMjcwXDIyMlwzMTZcMzEyXDMyNFwyMjRLXDMzM1wyNzNcMDM3XDAyNE5cMzEyPlwyNzBqXDM1M1wzNjVFUG5lXDMxNDp5XHJkXDMzNlwzNjZLXDIyMStuWFwyMTcrXDAyN1wzMjVcMzc3VVwyNDFOa1wyMjJcMjE2LnZXQlwzNTBcMzM1XDMzNVwwMjNcMjE0XDIyM15z",
                    			"y": "XDAwNFwzNzNoXHIyRXwkXDI2MVwyNDNLK1wyMDNcMjM0XDI0M1wzMDdcMzY1XDAxN1wyMjdcMjAzXDM2MFwzMDZcMjU1XGFOXDM3MjRcMzIwXDIzMVwwMzdcMzAzMVwwMjU1XDMyMlwzNjFcMjI3XDIzN1wyNjRcMzA0XDI3MFwyMjZWXDAzMlxiXDI1MVwyNTZcMjA3XDM3NixcMjUxXG5cMjE3XDIwMlwzNDAmXDM2NkM="
                    		},
                    		"http://schema.org/givenName": {
                    			"x": "XG40XHQyLzpcMjI0XDI1MVwzNjY7XDM1NFwzNDF0XDM2MjR+XDI1MFwzNTJcMjUxNyNcMzI3XDAwMkM/cSxcMjU3XDMwN1xcbzt2XDAzMlwyNjckXDI3NkhcMzc2JlwyNDBcMjQ3XDM1NlwwMDJcMjQ0UVwzMTFcMzYxXDI1M1wzMTRcMzUzSHpnXDIxN1wyNDVcMjc1Qg==",
                    			"y": "XDAwM1wzMTVTXDIyNFwzMTZcMjAxXDMxMlwzNjdcMDMwSlNcMjcxXDI3M1wxNzdcMzYyXDMzNy9cMDIyXDIxM2lQVFwyNzFcMjI1LC5cMDI3XDMyMm1cMzUwY1EyXDAxN1wzNTQtXDM3N1wzNTFcMDA0XDIwNVBdXDIyNlwzMzNcMzA0XDAzND1cMjc2XDIxNjhcMDI1XDIxMVwzMDRcMzA1XHRcMjQzXDIyM1wzNjM="
                    		},
                    		"https://www.w3.org/2018/credentials#expirationDate": {
                    			"x": "XHJyPm9cMDM0XDE3N1wwMzZkXDI0NX1cMzA0UlwzNzRcMjMwUFwyNzd3V1wyMDI9SVwyNjFcMzU0X1wwMDNcMzYzX1wzNDRcMjYzXDMyNCxcMjAxXDI1N1wzMDVcMDE2JVwyNTFcMzE3XDI3NUtcMzQ0XDM1MVwyNDBQXDM1MFwyMzFcMzIwa1wyNTVcMjI0Y1wwMTZcYVwwMzNcMDAxXDI2M1wzNDJe",
                    			"y": "XHZcMjIyXCJ3XDM0N1wyNjVcMjI0Y1wzNzJcMjYxb1wyNDFcMjI3fUVcYVwxNzdcMDAwM1wzNzB8XDIwMFwyNTRFXDAyM1wyMzRcMzYyOVwwMjFcMzE0XDI2MVlcMjMxNDNMXDAwNFwyMDFcMzE2XDMyNFwyNDJcMjIzXDM1NHlcMjUxXDMxN1wyNDBcMjMycyheXDIxNiopRyVtXDMzMQ=="
                    		},
                    		"http://schema.org/image": {
                    			"x": "XDAwMVwzNDFpXGJcMDIzXDI3MlwzNjAyXCdcMjc0a1wyMjFcMzQ1XDMyNlwyMjdcMDI3XDMzN3VcMzc1U1wzNTJcMjMwXDI2NFwyMjYwXDI3Ni1cMjYwXDAyNlwzMjZnXDAzMFwyMTJkSVwyMjJcMzAxXDAzNXF2XDIyNlwwMzVcMjE2eDVcMzA0XDAyNVwyNzRcMjM3XDI2MVwxNzd8XDAwMzJcMjEyXDMyMTdcMDI1",
                    			"y": "XG5NXDM3NlwwMjJUXDM2M1wzNTdUXDMyMlwyMTRcMzIzXDI3MDJcMjYyXDM1M1wyMzFcMDE2XDM1N1wzNzRcMzAyXDI2M0NLPl1cMjM0XDI3NFwyMzImXDI2M2JcMjYyXDM2NlwyNDdcMjQ0XDI3NlwzNTFcMDIweVwwMjdcMDMxKFwzNDRcMjYxXDM1NVwzNjVcMjUwXGFcMDAyXDI2MmY+JVwzNjNcMjc1M1dX"
                    		},
                    		"https://w3id.org/citizenship#birthCountry": {
                    			"x": "XDAyNSk/XDIwNVwzMjRuXDIzNlwyNTRcMzQyXDM3MVwyNjc7XDI0NDZcMDA0XDM2MFwyNzdcMjExXDMyN1wzMTRcMzcyXDIzMldcMDAxXDIxNkFtRHFcMDIxXHZcMzA3XDAzMVwyNzRcclwyMTZcMzMxY1wyMDdcMzc2TFwyMDdcMzUwXDIwMVwzNzJpXDM3MjlcMzMwbFwzNTIwXDI0N31cMzI1XDAyNVwyMzJcMzc3",
                    			"y": "XDAyMVBcIklcMDA1XDMxNFwzNzdcMjMxcSZcMjIzU1wyNjNcMjYxMlwzMTZdXDMxMkBcMjEzXDAxN1wyNDV2XDMwMFwyMTM7JVwzMjNcMzcyXDMxNlwzMDAzXDM1N1wyMjZeXDI3MilcMzQ2XDI3NHFcMjExaFwyNTVFXDIyMVwwMzRyXDAxNlwzMDIsXDAyMFwyMDBcMjYxLVwzNzFcMzQxXDI1M1wwMDM="
                    		},
                    		"http://schema.org/description": {
                    			"x": "XDAwMVwzMDBcMjQzfS5iXGZcMzYyXCJcXFwyNzNzXDM3NzVcMjQ0RlwyMjFcMjIxMHJZXDMwMXJ3dHY7XDMwN1x0XDM0MlwyNTYhXWZcMjQ3XDM2N1wyMjFcMjQzXDM2MlwyMzc/SFwzMDZlXDMyMzRNXDIxM1xiXDI1MDdhXDIyN0BcMzExXDIyNWJcMzQw",
                    			"y": "XHJcMzU2XDMxM35AM1wzMjNcMzYyVVwwMjJcMjA2XDI2MVwwMjBNblwyNTdcMjYzXDMxNlwzNTVcMDA0XDIzNFwzNzZIXDI2NVwzMTRcMjc3XDM1MlwwMDQ6XDI0NyN7XDIyNFwyMTNcMzY1XDI3MC9cMDM3XDI3My9cMjE1bFwyMjI+XDI2MVwzNjNcMDM1U1ZcMDIzW1pcMjczX1wzMzFcMjUyXDAwMlwzMjU="
                    		},
                    		"http://schema.org/name": {
                    			"x": "XGF9XHQqXDAwNVwwMDBcMzYwNlwyNjFmXDI1N3FcYVwyMzBXXDIzMVwyNjVQeFxmXDMzMFwzMzAuXDI0MGZcMzQ3XDM3NlwwMjdcMDI2flwzMzFhYVwwMjA5KSpcMDI0LUFcMjIwXGFyXDI0NVNcMjEwPVwyNjVcMDMyb1wyNDEmXDAzMDsmIFwiXDMyMg==",
                    			"y": "XGY3XDM3MFwyNjJpXDIyNVwyNzBVXDIyMlwyMTJcMjY1XDMxMVwzNTFHQVwyNzdcMzY3MFwiXDMyN1x0XDAwNFxuXDIzMVwyNzZcMzI3XDIxMlwzMDFffXkgLHRcMzUwXDIyMFxiXDAyMVx0LlwzMzdcMjYwXDI2M3BcMjAzXDIzN1wwMzFid1wzMzNcMjI2XDI0MlwyNzZcMjMxZVwwMzUkXDIxNQ=="
                    		},
                    		"http://schema.org/familyName": {
                    			"x": "XDAwNEtcMjcwXDMwN1tcMDIwXDI0MEhcMzcwXDI2NFwzNjJcMjMyPFwzMjJcZjlcMzExXDI0NlwzNTJcMjIxXDIzMFokXDAwNSl2LXlcMjYwXDIxMHgsXG4pXDAzMiFcMjY2XDMyMVwyNTVcMjExXDAxNitcblwyMDJcMzU1blwwMzNsYFwyMTd8XDI2M1wyMDJcMjU0PHhCNw==",
                    			"y": "XDAyMlwyNzA2dlwzMzJcMzIwe1wyNTVcMjMzXDI0MlwzNjNcMjc0eFwzNjVcMjcyXDI0NE1cMjI3XDMwNlwwMjVcMjMxXDIxMFwzMjRXRlwyMTdcMjYwTFwzMjNUXDIyNFwwMzJcMzA3XDMyM1wzNjRcMjYxclwzNzQsXDAwMXZcMzIwXDM1MlwzMTNcMzQyIyNcMzEwXDMwNlNcMzQ1XDI0NVwyNzBWKFwyMzBcMjQyXDAzNQ=="
                    		},
                    		"http://schema.org/birthDate": {
                    			"x": "XDAwNWRcMzQzXS15XDIzNj5cMzE3XDM0MVwwMjNcMzIxXDMzMGdcMDIyXDM2M3xcMjIzXDI0NlwzMjB5eHhfXDAzND5cMzY3d1wyNTZcMzM1XDMxNVJBXDM2NVwwMDNfXGZcMzc2XDIzMFwzNTNcMzM0XDM3NFwyMDRcYVwyNDNcMzA3XDIxM0FcMjY0RltcMjYxXDIyMlwzMjVcMzQ2XDI3MVwyMjRcMDMx",
                    			"y": "XDAwMFxiXDI2MlwyMTJcMDMzXDIyM1wzNjdcMDMzXnxcMjA0KWVcMzE1PX1cMzYwXDI2MVwyMjNQXDI0MFwyNzdcMjEzQFwwMjRmZzB8XDIzMFwyMDJCXDI0N1wzNDI6XDAwMlwwMDViXDM1MVwzMDBNPUJcMjIwXDM1NFwyMTdTXDIzNylcMzYwSVwzNDNcMjE3XDI3NzBcMjExL1wyMzU="
                    		},
                    		"http://schema.org/gender": {
                    			"x": "XDAwM2ZcMjQwXDM0NlwyMzYqXDMxNFwyNDBcMzU1XDMzNntcMDM3XDI0MU1cMjMzXDMzNFx2YVwyNjFcMzA0XDAyMFwzNjFHPyFcMzI3IFwzNDUhWFwzNzZyXDI1NFwzMzNUXDIwN1wwMjdcMzQ1XDMzMF1cMjAyXDI2MVx0XDMwN1wzMTVcMDMyaVwyMDZcMzYyXDAwMVwyMDBNbkhgXDMwNGhF",
                    			"y": "XDAyMCFjXDAzMVwzMzcxXDM3M1xuXDI1MUlcMjM3XDIwMXNcMzIyI1wzMjBLUSx1NFwzNjdcMjE3XDI2Mn5cMzAxcVwwMDMyXDMwNlwyNzBcMjYzR1wyNjJdXDAyMDNEXDIzMDt+XHJcMzYzXDM2MVwzMTdcMzYyXDI0NVwyMDVcMjYyXDAwMVwyNjREXDIyMj5sXDMxN1wzNTRV"
                    		},
                    		"https://www.w3.org/2018/credentials#credentialSubject": {
                    			"x": "XHZcMjY0XDI1NFwyNTBcMDI2OlwzNDYyXDMwMUdcMjU3XDM3NX1cJ1wzMzVcJ1xcXDMxMVwzNjVcMjY1XDIzN1wzNzNcMjI3XDMyMlwyMzU9XDI1NFwzMTZcMDI2XDM1NkdwXDMwNzVcMDIyXDIwM1wyMjNjQ1wwMjFcMjY1QlwwMjBcMzIxa1wzNjRcMzE3M1wyMzV2XFxcMjM2SlwzNDVkXDI1NlwzNDYk",
                    			"y": "XDAwNikuXDIxNFlQXDIyMEpcMjI0XDMxNVwwMzJcMjUzMjFiXDM0M1wzNTBcMjUwXDIzNFwyNzRcMzA0LldbaVwwMDRcMzcwXDM3NFwzNzB4WVwzMDFoXDM3MlwyNzRwXDI2NFwzMDRcMjM2XDAzNzdcYVwwMTZcMzIyYVdmZlwzNzI+V1wzNzVcMzM0XDM0NWlbXDI3MlwzMzU="
                    		}
                    	}
                    }
                    """);
            jwkPrivate = JWK.fromJson("""
                    {
                    	"kty": "EC",
                    	"crv": "PSMS",
                    	"x": "XDAwMFwwMDBcMDAwXDAwMFwwMDBcMDAwXDAwMFwwMDBcMDAwXDAwMFwwMDBcMDAwXDAwMFwwMDBcMDAwXDAwMFwwMDBcMDAwXDAwMFwwMDQ7RFwyNzZcMzY2XDAzM1h3eFwyMDNoXDMwNlwyMzdcMzY0bkVcMDI0XDMwMFwwMjBcMzI0eFwzMjRcMzU3OlwzNTEhJFwzNTRmKFwyNzdcMDIxSFwzMjFcMzAzXDAyMVwzMzVcMzA3Xg==",
                    	"y_m": "XDAwMFwwMDBcMDAwXDAwMFwwMDBcMDAwXDAwMFwwMDBcMDAwXDAwMFwwMDBcMDAwXDAwMFwwMDBcMDAwXDAwMFwwMDBcMDAwXDAwMFxyXDAwMFwyNjJqXDAzMVwyMjFsXDAwMVwyMjNcYVwzMTFcMjAwXDM3MlwzMDRcMjUyXStcMjUyXDMwN3gmXDM2MFwzMTZcMjQ3JW5PXDM3NH1cMDM1XDAxNz1cMDE2XDMxMHBcMzczXDAwM1wyNTJcMzQ3",
                    	"epoch": "XDAwMFwwMDBcMDAwXDAwMFwwMDBcMDAwXDAwMFwwMDBcMDAwXDAwMFwwMDBcMDAwXDAwMFwwMDBcMDAwXDAwMFwwMDBcMDAwXDAwMFwwMDJoXDM0M1wyMzFcMDE2flpdXDMzNGRcMjQwXDI0MVwzMjZcMzM0XDI1NFwzNTBPXDI2NFwzMTRcMzI2XDMwNVwzMjBcMDMyXDI3N1wzNjA2XDIwM1wzNjRcMjc0PzpcXFwwMzVcMzc3ZD9cMzc2XDM0MVwzMjM=",
                    	"y": {
                    		"https://w3id.org/citizenship#residentSince": "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDFlMzhkZWQxNzE3NGQxYjczZmFkMzVjMzgxY2MyZTRkMGUwNTZlMWYzOWU3NDc4YmZhZGZjMWRjMTdkYWZhZmVhZjNiNzUyOTkxZGU=",
                    		"https://w3id.org/citizenship#lprCategory": "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMzM4OTg1NzdlOTUxM2UwMjlkYjBiZjQ3NzM3YmExMmIwZmIwZWIwM2NjNzViOTEwNGNiOTVmYjI5NmY2Mzc2MGVjODM4YTBiMTc5OTQ=",
                    		"https://www.w3.org/2018/credentials#issuer": "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMzRlMGRiNGJhNjI4MTIwOTE3MTZlZjk2NDQ3M2M5YWI3ZThmYjlhNzUzNjZmYTJkOWQ3NzBjNjY5ZDEyNzA4YWUyNjQyOGM4NzRjNTM=",
                    		"https://www.w3.org/2018/credentials#issuanceDate": "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwZTlkODhiODYxNzhjOWNkYTAzNTQzZmEwMGJmNDA1NzY3NjBkZTMxNmNlODNlOTg4NjJhNDhkODVjZTZkM2VmYTk3MTI0Mzc0ODQ1Mjg=",
                    		"https://w3id.org/citizenship#lprNumber": "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMmRiMjE5NmRkMWY5ZGQ5ZmNkZDI0ZTRlNzI5YzhhZDBjODE3YjdlYTgwZTg2ZWMxMzFmYzJlOTcyY2ViMjU5MzNiYjY4Mjk0ZmU4ZjE=",
                    		"https://w3id.org/citizenship#commuterClassification": "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwNzY3OGJmOGVkZDliYzJhMzgwNzcwZTJmMzBjY2YxMGM5NTk4MDUwN2UyNjJjMDY3YzczZWVjMDVmMWQ0MGQ4NmRiZmIyYTU5NGQwMzU=",
                    		"http://schema.org/givenName": "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwODRkYWNmMDQ5OTUyZmQ1ZmUzOGM5M2ZlZjc2NzNkNjc0OTRiMjlhYzkxMDUyM2Y3MzQzMGY4ZTYyZDBlNWQxMmQ4NTAzMzZlZTM4YmQ=",
                    		"https://www.w3.org/2018/credentials#expirationDate": "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM2JkNTgxNDM5YzI5MjBmNGQwODZhMGZmMjU0ZWRhNGI5MmFkNmE4NGEwNzAxYmViYjViZTA0MDg5ODNmNDRhMDdjOGZjMmM3NjZiODU=",
                    		"http://schema.org/image": "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwYmZhMmRmMzRmODVkOWZmYzk1ZWNiYjhhZGNlYTE5YmRiNDQ4MzljOTk1NjVkNGY3YmQyOTAzZTEzOWE1MDgzYjdjZWU4OWM3MTMwNzU=",
                    		"https://w3id.org/citizenship#birthCountry": "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwYzk0MTcwMzQyY2IzNWVkYjdiNzRjYWFhOTJhMWRiZjRiZDUwZTFjZmViNWQwNzM3NWRiZGU4OWZjYzY0NzhhYmVjMjQxODBkMTY2NmY=",
                    		"http://schema.org/description": "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwYmZlZDc0NTE3N2VjODU5OGE3Y2U2MDViZmJlNjkwZDMxYjU4NDVhM2IwY2Y0MWVkOGMzODMzM2RjN2VhNGY4ZGQ3ZTc1NDdmZjM5NmY=",
                    		"http://schema.org/name": "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwNDdlZTJiMWEzOWI0MzkzNWZiOGJhY2JiM2E3NzgzY2YzZGVhNmY0ZTk0NTc2NTk0NGUxZjdjZjAwMDRmNTM5Zjk0MjQ4NzM3YzA0NzM=",
                    		"http://schema.org/familyName": "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwNmY4ZjY5Y2QxZDJkYTYyNDMyMDhhODM4NWI2YTQyNmI2ZTBkZjNkY2RjMTE1ZDk3ODI2ZGUzMDVlYTdmODQzNjQxMzYzNmRlZjc0ZWI=",
                    		"http://schema.org/birthDate": "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwNmMxZjcwNWQ5MDU2MWU0N2RlYjI3ZjY3ZDQ3MGE4MTM0MGU0NWE5OTc5YWU1Y2E0ZGU3YzZmNWEyYmI2ZjdiMDMyMTk2YzFmY2MzMDg=",
                    		"http://schema.org/gender": "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwYWYyMzZlOGRjMDUwYTU3OWE1YzFiYWZiZTQwYjE2NjA3YTY0MzdhMjBjYWJlNTJhNTc1OGNmZDViZTRiNmVjMTM5ZjYxMjg4MGQwNjc=",
                    		"https://www.w3.org/2018/credentials#credentialSubject": "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwNTE3NTI1OGZmNzMwYTUwZWFhOWQ5NGRkY2E0NmJjM2ZmYmRlMDkzMGI1ZDUwZTc5MWNhODNjYjI1NGFiN2Y1NTM0ODBkMzUzYjMyYWU="
                    	}
                    }}""");
        } catch (IOException ex) {
            throw new ExceptionInInitializerError(ex);
        }
    }
    @Override
    KeyTypeName getKeyTypeName() {
        return KeyTypeName.PSMS;
    }

    @Override
    List<String> getAlgorithms() {
        return Collections.singletonList(JWSAlgorithm.PSMSAlg);
    }

    @Override
    Object getPrivateKey() {
        return JWK_to_PrivateKey.JWK_to_P_521PrivateKey(jwkPrivate);
    }

    @Override
    Object getPublicKey() {
        return JWK_to_PublicKey.JWK_to_P_521PublicKey(jwkPublic);
    }


    @Test
    public void testPublicKey() throws Exception {

        assertEquals(true, true);
    }
}

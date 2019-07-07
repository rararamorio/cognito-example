package jp.example.morio.example.cognito;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

import org.apache.commons.codec.binary.Base64;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * token check sample
 *
 */
public class App {

    public static void main(String[] args) {
        App app = new App();
        app.execute();
    }

    private void execute() {

        String jwksUrl = "https://cognito-idp.{region}.amazonaws.com/{user-pool-id}/.well-known/jwks.json";
        ObjectMapper mapper = new ObjectMapper();
        JsonNode node;
        try {
            node = mapper.readTree(new URL(jwksUrl));
            JsonNode keys0 = node.get("keys").get(0);
            System.out.println(String.format("key0 = %s", keys0));

            var modulus = decodeBase64(keys0.get("n").asText());
            var exponent = decodeBase64(keys0.get("e").asText());
            System.out.println(modulus);
            System.out.println(exponent);

            RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(modulus, exponent);
            System.out.println(pubKeySpec);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKey publicKey = (RSAPublicKey)keyFactory.generatePublic(pubKeySpec);

            System.out.println("jwt");

            String idToken = "idTokenxxx";
            DecodedJWT decode = JWT.decode(idToken);

            // privateKeyどうしよう
            Algorithm algorithm = Algorithm.RSA256(publicKey);
            JWTVerifier verifier = JWT.require(algorithm)
                    .build();

            DecodedJWT jwt = verifier.verify(idToken);
            System.out.println(jwt.getHeader());
            System.out.println(jwt.getPayload());

            byte[] bytes = Base64.decodeBase64(jwt.getPayload());
            String result = new String(bytes, StandardCharsets.UTF_8);
            System.out.println(result);
        } catch (IOException e) {
            // TODO 自動生成された catch ブロック
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            // TODO 自動生成された catch ブロック
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            // TODO 自動生成された catch ブロック
            e.printStackTrace();
        }
    }

    private BigInteger decodeBase64(String n) {
        return new BigInteger(1, Base64.decodeBase64(n));
    }


}

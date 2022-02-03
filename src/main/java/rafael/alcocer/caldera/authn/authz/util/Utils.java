/**
 * Copyright [2022] [RAFAEL ALCOCER CALDERA]
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package rafael.alcocer.caldera.authn.authz.util;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;

/**
 * https://github.com/jwtk/jjwt
 * 
 * SecretKey Formats
 * 
 * If you want to sign a JWS using HMAC-SHA algorithms and you have a secret key
 * String or encoded byte array, you will need to convert it into a SecretKey
 * instance to use as the signWith method argument.
 * 
 * @author Rafael Alcocer Caldera
 * @version 1.0
 */
public final class Utils {

    private static final Logger LOGGER = LoggerFactory.getLogger(Utils.class);

    private Utils() {
    }

    /**
     * Secret Keys
     * 
     * If you want to generate a sufficiently strong SecretKey for use with the JWT
     * HMAC-SHA algorithms, use the Keys.secretKeyFor(SignatureAlgorithm) helper
     * method:
     * 
     * SecretKey secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256); //or HS384
     * or HS512
     * 
     * Under the hood, JJWT uses the JCA provider's KeyGenerator to create a
     * secure-random key with the correct minimum length for the given algorithm.
     * 
     * @param alg
     * @return
     */
    public static SecretKey generateSecretKey(SignatureAlgorithm alg) {
        return Keys.secretKeyFor(alg);
    }

    /**
     * If you need to save this new SecretKey, you can Base64 (or Base64URL) encode
     * it:
     * 
     * String secretString = Encoders.BASE64.encode(key.getEncoded());
     * 
     * Ensure you save the resulting secretString somewhere safe - Base64-encoding
     * is not encryption, so it's still considered sensitive information. You can
     * further encrypt it, etc, before saving to disk (for example).
     * 
     * @param key
     * @return secretString
     */
    public static String generateSecretKeyToBeSaved(Key key) {
        return Encoders.BASE64.encode(key.getEncoded());
    }

    /**
     * If your secret key is an encoded byte array:
     * 
     * SecretKey key = Keys.hmacShaKeyFor(encodedKeyBytes);
     * 
     * @param encodedKeyBytes
     * @return SecretKey
     */
    public static SecretKey getSecretKeyFromEncodedByteArray(byte[] encodedKeyBytes) {
        return Keys.hmacShaKeyFor(encodedKeyBytes);
    }

    /**
     * If your secret key is a Base64-encoded string:
     * 
     * SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretString));
     * 
     * @param secretString
     * @return SecretKey
     */
    public static SecretKey getSecretKeyFromEncodedBase64String(String secretString) {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretString));
    }

    /**
     * If your secret key is a Base64URL-encoded string:
     * 
     * SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64URL.decode(secretString));
     * 
     * @param secretString
     * @return SecretKey
     */
    public static SecretKey getSecretKeyFromEncodedBase64UrlString(String secretString) {
        return Keys.hmacShaKeyFor(Decoders.BASE64URL.decode(secretString));
    }

    /**
     * If your secret key is a raw (non-encoded) string (e.g. a password String):
     * 
     * SecretKey key =
     * Keys.hmacShaKeyFor(secretString.getBytes(StandardCharsets.UTF_8));
     * 
     * @param secretString
     * @return SecretKey
     */
    public static SecretKey getSecretKeyFromRawString(String secretString) {
        return Keys.hmacShaKeyFor(secretString.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * 
     * @param encoded
     * @return
     */
    public static byte[] getByteArrayFromEncodedString(String encoded) {
        return Decoders.BASE64.decode(encoded);
    }
    
    /**
     * 
     * @param key
     * @param id
     * @param issuer
     * @param subject
     * @param expiration
     * @return
     */
    public static String generateJWT(Key key, String id, String issuer, String subject, Date expiration) {
        List<GrantedAuthority> grantedAuthorities = AuthorityUtils
                .commaSeparatedStringToAuthorityList("ROLE_USER");
        return Jwts.builder()
                .signWith(key)
                .setId(id)
                .setIssuer(issuer)
                .setSubject(subject)
                .setExpiration(expiration)
                .claim("authorities",
                        grantedAuthorities.stream()
                                        .map(GrantedAuthority::getAuthority)
                                        .collect(Collectors.toList()))
                .compact();
    }

    /**
     * 
     * @param key
     * @param signatureAlgorithm
     * @param id
     * @param issuer
     * @param subject
     * @param expiration
     * @return
     */
    public static String generateJWT(Key key, SignatureAlgorithm signatureAlgorithm, String id, String issuer, String subject, Date expiration) {
        List<GrantedAuthority> grantedAuthorities = AuthorityUtils
                .commaSeparatedStringToAuthorityList("ROLE_USER");
        return Jwts.builder()
                .signWith(key, signatureAlgorithm)
                .setId(id)
                .setIssuer(issuer)
                .setSubject(subject)
                .setExpiration(expiration)
                .claim("authorities",
                        grantedAuthorities.stream()
                                        .map(GrantedAuthority::getAuthority)
                                        .collect(Collectors.toList()))
                .compact();
    }

    public static Jws<Claims> verifyJWT(Key key, String jwtString) {
        Jws<Claims> jws = null;

        try {
            jws = Jwts.parserBuilder()
            .setSigningKey(key)
            .build()  
            .parseClaimsJws(jwtString);
            // we can safely trust the JWT
        } catch (JwtException ex) {
            // we *cannot* use the JWT as intended by its creator
            LOGGER.error("##### We cannot trust this JWT: " + ex.getMessage());
        }
        
        return jws;
    }
    
    /**
     * Generates UUID dash-less string.
     * 
     * Instead of 44e128a5-ac7a-4c9a-be4c-224b6bf81b20
     * 
     * is 44e128a5ac7a4c9abe4c224b6bf81b20
     * 
     * @return UUID String
     */
    public static String generateUUID() {
        return UUID.randomUUID().toString().replace("-", "");
    }
    
    /**
     * Returns Date plus minutes added.
     * 
     * @param minutes
     * @return
     */
    public static Date getDatePlusMinutesAdded(int minutes) {
        LocalDateTime dateTime = LocalDateTime.now().plus(Duration.of(minutes, ChronoUnit.MINUTES));
        
        return Date.from(dateTime.atZone(ZoneId.systemDefault()).toInstant());
    }
}

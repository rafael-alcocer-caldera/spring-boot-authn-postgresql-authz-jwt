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
package rafael.alcocer.caldera.authn.authz.controller;

import java.util.Date;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import lombok.RequiredArgsConstructor;
import net.sf.json.JSONObject;
import rafael.alcocer.caldera.authn.authz.configuration.WebSecurityConfiguration;
import rafael.alcocer.caldera.authn.authz.model.User;
import rafael.alcocer.caldera.authn.authz.payload.request.AuthenticationRequest;
import rafael.alcocer.caldera.authn.authz.util.Utils;

@RequiredArgsConstructor
@RestController
public class AuthnAuthzController {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthnAuthzController.class);
    private final WebSecurityConfiguration webSecurityConfiguration;
    private final RestTemplate restTemplate;
    private final HttpHeaders httpHeaders;
    private final User user;

    @PostMapping("authorization")
    public ResponseEntity<?> login(@RequestBody AuthenticationRequest request) {
        LOGGER.info("##### username: " + request.getUsername());
        LOGGER.info("##### password: " + request.getPassword());
        LOGGER.info("##### webSecurityConfiguration.getSecretKey(): " + webSecurityConfiguration.getSecretKey());

        /*
         * **************************************************************************
         * 
         * Here we are calling the Authentication PostgresQL Service
         * spring-boot-authentication-postgresql
         * 
         * **************************************************************************
         */
        try {
            HttpEntity<AuthenticationRequest> entity = new HttpEntity<AuthenticationRequest>(request, httpHeaders);

            JSONObject responseBody = restTemplate.exchange(webSecurityConfiguration.getAuthenticationUrl(), HttpMethod.POST,
                    entity, JSONObject.class).getBody();

            LOGGER.info("##### responseBody: " + responseBody);
            LOGGER.info("##### responseBody.getString(\"username\"): " + responseBody.getString("username"));
            LOGGER.info("##### responseBody.getString(\"authorities\"): " + responseBody.getString("authorities"));
            LOGGER.info(
                    "##### responseBody.getJSONArray(\"authorities\"): " + responseBody.getJSONArray("authorities"));
            LOGGER.info("##### responseBody.getJSONArray(\"authorities\").size(): "
                    + responseBody.getJSONArray("authorities").size());
            LOGGER.info("##### responseBody.getJSONArray(\"authorities\").getJSONObject(0): "
                    + responseBody.getJSONArray("authorities").getJSONObject(0));
            LOGGER.info("##### responseBody.getJSONArray(\"authorities\").getJSONObject(0).getString(\"authority\"): "
                    + responseBody.getJSONArray("authorities").getJSONObject(0).getString("authority"));
        } catch (HttpClientErrorException ex) {
            LOGGER.error(webSecurityConfiguration.getAuthenticationErrorMessage());
            
            user.setUsername(request.getUsername());
            user.setJwt(webSecurityConfiguration.getAuthenticationErrorMessage());

            return new ResponseEntity<>(user, HttpStatus.UNAUTHORIZED);
        }

        /*
         * **************************************************************************
         * 
         * If the above code has no exceptions, the following code will generate the JWT
         * 
         * **************************************************************************
         */
        SecretKey secretKey = Utils.getSecretKeyFromEncodedBase64String(webSecurityConfiguration.getSecretKey());

        Date dateTime = Utils.getDatePlusMinutesAdded(webSecurityConfiguration.getMinutes());
        LOGGER.info("##### dateTime (including minutes added: " + dateTime);

        String jwt = Utils.generateJWT(secretKey, Utils.generateUUID(), webSecurityConfiguration.getIssuer(),
                webSecurityConfiguration.getSubject(), dateTime);
        LOGGER.info("##### JWT: " + jwt);
        
        user.setUsername(request.getUsername());
        user.setJwt(jwt);

        return new ResponseEntity<>(user, HttpStatus.OK);
    }
}

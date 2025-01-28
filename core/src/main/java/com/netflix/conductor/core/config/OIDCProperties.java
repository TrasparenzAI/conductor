/*
 *  Copyright 2025 Conductor authors
 *  <p>
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 *  the License. You may obtain a copy of the License at
 *  <p>
 *  http://www.apache.org/licenses/LICENSE-2.0
 *  <p>
 *  Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 *  an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 *  specific language governing permissions and limitations under the License.
 */
package com.netflix.conductor.core.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Collections;
import java.util.Map;

@Setter
@Getter
@ConfigurationProperties("conductor.security.oidc")
public class OIDCProperties {

    private boolean enabled = Boolean.FALSE;
    /**
     * Name of the client registration ID for webclient
     */
    private String clientRegistrationId = "oidc";
    /**
     * Name of the roles
     */
    private Map<String, String[]> roles = Collections.emptyMap();

    private int clientMaxInMemorySize = 2 * 1024 * 1024;

}

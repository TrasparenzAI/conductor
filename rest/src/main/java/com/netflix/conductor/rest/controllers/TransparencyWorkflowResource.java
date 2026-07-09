/*
 * Copyright 2025 Conductor Authors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package com.netflix.conductor.rest.controllers;

import java.util.List;

import com.netflix.conductor.core.config.OIDCProperties;
import jakarta.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.netflix.conductor.common.metadata.workflow.StartWorkflowRequest;
import com.netflix.conductor.service.WorkflowService;

import io.swagger.v3.oas.annotations.Operation;
import lombok.extern.slf4j.Slf4j;

import static org.springframework.http.MediaType.TEXT_PLAIN_VALUE;

/**
 * Espone l'avvio del workflow "crawler_amministrazione_trasparente" riusando {@link
 * StartWorkflowRequest} (lo stesso contratto usato da {@link WorkflowResource}), limitandolo agli
 * utenti che:
 * 1) possiedono il ruolo configurato in {@code conductor.security.oidc.rpct_role_name}, e
 * 2) hanno, tra i claim del proprio JWT (chiave configurata in
 * {@code conductor.security.oidc.ipa-claim}), il codice IPA richiesto (chiave
 * "codice_ipa" nella mappa di input).
 *
 * <p>Il client valorizza {@code request.input} con le chiavi snake_case previste dalla
 * definizione del workflow (page_size, codice_ipa, codice_categoria, crawling_mode,
 * crawler_save_object, crawler_save_screenshot, rule_name, root_rule, execute_child,
 * id_ipa_from, connection_timeout, read_timeout, connection_timeout_max, read_timeout_max,
 * force_jsoup, rule_base_url, public_company_base_url, result_aggregator_base_url,
 * result_base_url, crawler_child_type, crawler_uri), esattamente come farebbe con l'endpoint
 * generico di WorkflowResource. {@code name} e {@code version} vengono forzati lato server per
 * evitare che, tramite questo endpoint "autorizzato per IPA", si possa avviare un workflow
 * diverso da quello previsto.
 */
@RestController
@RequestMapping("/api/transparency")
@Slf4j
public class TransparencyWorkflowResource {

    // Nome del workflow definito in crawler_amministrazione_trasparente.json
    private static final String WORKFLOW_NAME = "crawler_amministrazione_trasparente";

    // Chiave, nella mappa di input, del codice IPA per cui si vuole avviare il crawling
    private static final String INPUT_CODICE_IPA = "codice_ipa";

    private final WorkflowService workflowService;
    private final OIDCProperties properties;

    public TransparencyWorkflowResource(
            WorkflowService workflowService, OIDCProperties properties) {
        this.workflowService = workflowService;
        this.properties = properties;
    }

    @PostMapping(value = "/start", produces = TEXT_PLAIN_VALUE)
    @Operation(
            summary =
                    "Avvia il crawler di Amministrazione Trasparente per il codice IPA presente "
                            + "in request.input.codice_ipa, solo se l'utente autenticato è "
                            + "autorizzato per quel codice IPA")
    public String startTransparencyWorkflow(
            @RequestBody @Valid StartWorkflowRequest request, @AuthenticationPrincipal Jwt jwt) {

        // Il workflow è fisso: il chiamante non può usare questo endpoint per avviarne un altro
        request.setName(WORKFLOW_NAME);

        Object codiceIpaValue = request.getInput().get(INPUT_CODICE_IPA);
        if (!(codiceIpaValue instanceof String codiceIpa) || codiceIpa.isBlank()) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "input.codice_ipa è obbligatorio e deve essere una stringa non vuota");
        }

        checkIpaAuthorized(jwt, codiceIpa);

        return workflowService.startWorkflow(request);
    }

    /**
     * Verifica che il codice IPA richiesto sia presente nella lista dei codici IPA autorizzati
     * per l'utente, letta dal claim configurato in {@code conductor.security.oidc.ipa-claim}.
     */
    private void checkIpaAuthorized(Jwt jwt, String codiceIpa) {
        List<String> allowedIpaCodes = jwt.getClaimAsStringList(properties.getIpaClaim());

        if (allowedIpaCodes == null || !allowedIpaCodes.contains(codiceIpa)) {
            log.warn(
                    "Utente {} non autorizzato per il codice IPA {}",
                    jwt.getSubject(),
                    codiceIpa);
            throw new ResponseStatusException(
                    HttpStatus.FORBIDDEN,
                    "Utente non autorizzato ad avviare il workflow per il codice IPA: "
                            + codiceIpa);
        }
    }
}

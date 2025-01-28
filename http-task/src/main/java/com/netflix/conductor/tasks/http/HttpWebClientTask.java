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
package com.netflix.conductor.tasks.http;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.netflix.conductor.core.execution.WorkflowExecutor;
import com.netflix.conductor.model.TaskModel;
import com.netflix.conductor.model.WorkflowModel;
import com.netflix.conductor.tasks.http.providers.RestTemplateProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClientRequest;

import java.time.Duration;
import java.util.Optional;

import static com.netflix.conductor.common.metadata.tasks.TaskType.TASK_TYPE_HTTP_WEBCLIENT;

/**
 * Task that enables calling another HTTP endpoint as part of its execution
 */
@Component(TASK_TYPE_HTTP_WEBCLIENT)
public class HttpWebClientTask extends HttpTask {

    private static final Logger LOGGER = LoggerFactory.getLogger(HttpWebClientTask.class);

    @Autowired(required = false)
    private WebClient webClient;

    @Autowired
    public HttpWebClientTask(RestTemplateProvider restTemplateProvider, ObjectMapper objectMapper) {
        super(TASK_TYPE_HTTP_WEBCLIENT, restTemplateProvider, objectMapper);
    }

    @Override
    public void start(WorkflowModel workflow, TaskModel task, WorkflowExecutor executor) {
        super.start(workflow, task, executor);
    }

    @Override
    protected HttpResponse httpCall(Input input) throws Exception {
        WebClient.RequestBodySpec requestBodySpec = webClient
                .method(HttpMethod.valueOf(input.getMethod()))
                .uri(input.getUri())
                .httpRequest(httpRequest -> {
                    HttpClientRequest reactorRequest = httpRequest.getNativeRequest();
                    Optional.ofNullable(input.getReadTimeOut())
                            .ifPresent(timeout -> reactorRequest.responseTimeout(Duration.ofMillis(timeout)));
                })
                .headers(httpHeaders -> {
                    input.getHeaders().forEach(
                            (key, value) -> {
                                if (value != null) {
                                    httpHeaders.add(key, value.toString());
                                }
                            });
                });
        Optional.ofNullable(input.getBody()).ifPresent(requestBodySpec::bodyValue);
        Optional.ofNullable(input.getContentType()).ifPresent(s -> {
            requestBodySpec.contentType(MediaType.valueOf(s));
        });
        Optional.ofNullable(input.getAccept()).ifPresent(s -> {
            requestBodySpec.accept(MediaType.valueOf(s));
        });
        return
                requestBodySpec
                        .retrieve()
                        .bodyToMono(JsonNode.class)
                        .map(jsonNode -> {
                            HttpResponse resp = new HttpResponse();
                            resp.statusCode = HttpStatus.OK.value();
                            resp.body = jsonNode;
                            return resp;
                        })
                        .onErrorResume(WebClientResponseException.class, e -> {
                            HttpResponse resp = new HttpResponse();
                            resp.statusCode = e.getStatusCode().value();
                            resp.body = e.getLocalizedMessage();
                            return Mono.just(resp);
                        })
                        .block();
    }

}

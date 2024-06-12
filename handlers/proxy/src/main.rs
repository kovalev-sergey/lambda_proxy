//! # AWS Lambda Proxy
//!
//! This AWS Lambda function, written in Rust, acts as a proxy for REST APIs. It forwards incoming HTTP requests
//! to a specified target host. The target host can be set either via a header (`X-Target-Host`) or an environment
//! variable (`TARGET_HOST`). The function also checks for an API key in the header (`X-API-Key`) to authorize requests
//! and prevents recursive calls by ensuring the target host is not the same as the source host.
//!
//! ## Dependencies
//! Make sure to include the following dependencies in your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! lambda_runtime = "0.5.0"
//! lambda_http = "0.6.1"
//! serde = { version = "1.0", features = ["derive"] }
//! serde_json = "1.0"
//! reqwest = { version = "0.11", features = ["blocking", "json"] }
//! log = "0.4"
//! simple_logger = "1.11.0"
//! tokio = { version = "1", features = ["full"] }
//! ```
//!
//! ## Environment Variables
//! - `TARGET_HOST`: (Optional) The default target host to forward requests to if the `X-Target-Host` header is not provided.
//! - `API_KEY`: (Required) The API key to authorize incoming requests.
//!
//! ## Headers
//! - `X-API-Key`: (Required) The API key provided by the client for authorization.
//! - `X-Target-Host`: (Optional) The target host to forward requests to. Overrides the `TARGET_HOST` environment variable.
//!
//! ## How It Works
//!
//! 1. **Authorization**: The function checks for an `X-API-Key` header and compares it with the `API_KEY` environment variable. If the API keys do not match, it returns a `401 Unauthorized` response.
//! 2. **Target Host**: The target host for forwarding the request can be specified via the `X-Target-Host` header. If the header is not present, the function uses the `TARGET_HOST` environment variable.
//! 3. **Recursion Prevention**: The function checks if the target host is the same as the source host (extracted from the `domainName` in `requestContext`). If they match, it returns a `400 Bad Request` response to prevent recursive calls.
//! 4. **Forwarding Request**: The function forwards the incoming HTTP request to the target host, including headers and body. It handles various HTTP methods (`GET`, `POST`, `PUT`, `DELETE`) and returns the response from the target host back to the client.
//! 5. **Error Handling**: If there is an error making the request to the target host, the function logs the error and returns a `502 Bad Gateway` response with an error message.
//!
//! ## Deployment
//!
//! 1. **Build the Rust project for AWS Lambda**:
//!    ```sh
//!    cargo build --release --target x86_64-unknown-linux-musl
//!    ```
//!
//! 2. **Create a deployment package**:
//!    ```sh
//!    mkdir lambda
//!    cp target/x86_64-unknown-linux-musl/release/lambda_proxy ./lambda/bootstrap
//!    cd lambda
//!    zip ../lambda_proxy.zip bootstrap
//!    cd ..
//!    ```
//!
//! 3. **Create an AWS Lambda function**:
//!    - Go to the AWS Lambda console.
//!    - Create a new function with a custom runtime.
//!    - Upload `lambda_proxy.zip` as the deployment package.
//!
//! 4. **Set the handler to `bootstrap`**:
//!    - In the Lambda function configuration, set the handler to `bootstrap`.
//!
//! 5. **Set environment variables**:
//!    - `API_KEY`: Set this to the expected API key for authorizing requests.
//!    - `TARGET_HOST` (optional): Set this to the default target host if the `X-Target-Host` header is not provided.
//!
//! 6. **Configure API Gateway**:
//!    - Create an API Gateway and configure it to trigger the Lambda function.
//!    - Ensure that the API Gateway passes the request details, including headers and request context, to the Lambda function.

use async_trait::async_trait;
use lambda_http::http::Method;
use lambda_http::http::{
    response::Builder as ResponseBuilder, HeaderName, HeaderValue, StatusCode,
};
use lambda_http::RequestExt;
use lambda_http::{lambda_runtime::Error, service_fn, tracing, Request, Response};
use reqwest::{Client, ClientBuilder, Response as ReqwestResponse};
use std::env;
use tracing::info;

#[async_trait]
pub trait HttpClient: Send + Sync {
    async fn get(
        &self,
        url: &str,
        headers: reqwest::header::HeaderMap,
    ) -> Result<ReqwestResponse, reqwest::Error>;
    async fn post(
        &self,
        url: &str,
        headers: reqwest::header::HeaderMap,
        body: Vec<u8>,
    ) -> Result<ReqwestResponse, reqwest::Error>;
    async fn put(
        &self,
        url: &str,
        headers: reqwest::header::HeaderMap,
        body: Vec<u8>,
    ) -> Result<ReqwestResponse, reqwest::Error>;
    async fn delete(
        &self,
        url: &str,
        headers: reqwest::header::HeaderMap,
        body: Vec<u8>,
    ) -> Result<ReqwestResponse, reqwest::Error>;
}

#[async_trait]
impl HttpClient for Client {
    async fn get(
        &self,
        url: &str,
        headers: reqwest::header::HeaderMap,
    ) -> Result<ReqwestResponse, reqwest::Error> {
        Client::get(self, url).headers(headers).send().await
    }
    async fn post(
        &self,
        url: &str,
        headers: reqwest::header::HeaderMap,
        body: Vec<u8>,
    ) -> Result<ReqwestResponse, reqwest::Error> {
        Client::post(self, url)
            .headers(headers)
            .body(body)
            .send()
            .await
    }
    async fn put(
        &self,
        url: &str,
        headers: reqwest::header::HeaderMap,
        body: Vec<u8>,
    ) -> Result<ReqwestResponse, reqwest::Error> {
        Client::put(self, url)
            .headers(headers)
            .body(body)
            .send()
            .await
    }
    async fn delete(
        &self,
        url: &str,
        headers: reqwest::header::HeaderMap,
        body: Vec<u8>,
    ) -> Result<ReqwestResponse, reqwest::Error> {
        Client::delete(self, url)
            .headers(headers)
            .body(body)
            .send()
            .await
    }
}

/// Handles the response from the target host by extracting the status code, headers, and body.
///
/// # Arguments
///
/// * `response` - A `reqwest::blocking::Response` object representing the response from the target host.
///
/// # Returns
///
/// A `lambda_http::Response` object that the Lambda function will return.

async fn handle_response(
    response: ReqwestResponse,
) -> Result<Response<String>, Box<dyn std::error::Error + Send + Sync>> {
    let status = StatusCode::from_u16(response.status().as_u16())?;
    let mut builder = ResponseBuilder::new().status(status);

    for (key, value) in response.headers() {
        if key == "host" {
            continue;
        };
        let header_name = HeaderName::from_bytes(key.as_ref())?;
        let header_value = HeaderValue::from_str(value.to_str()?)?;
        builder = builder.header(header_name, header_value);
    }

    let body = response.text().await.unwrap_or_default();
    info!("Output response body:\n{:?}\nHeaders:\n{:?}", &body, &builder.headers_ref());
    builder
        .body(body)
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
}

/// The main handler function for the Lambda function.
///
/// This function processes the incoming request, validates the API key, checks for recursion,
/// forwards the request to the target host, and returns the response.
///
/// # Arguments
///
/// * `event` - A `lambda_http::Request` object representing the incoming request.
/// * `context` - A `lambda_runtime::Context` object providing information about the invocation, function, and execution environment.
///
/// # Returns
///
/// A `Result` containing a `lambda_http::Response` object or an `Error`.
async fn function_handler(
    event: Request,
    client: &dyn HttpClient,
) -> Result<Response<String>, Error> {
    info!("Input request: {:?}", event);

    let expected_api_key = env::var("API_KEY").unwrap_or_default();
    let received_api_key = event
        .headers()
        .get("X-API-Key")
        .and_then(|value| value.to_str().ok());

    // Check if the received API key matches the expected API key
    if expected_api_key.is_empty() || received_api_key != Some(expected_api_key.as_str()) {
        return Ok(Response::builder()
            .status(401)
            .body("Unauthorized".to_string())
            .expect("Failed to render response"));
    }

    // Extract the target host from the headers
    let target_host_header = event
        .headers()
        .get("X-Target-Host")
        .and_then(|value| value.to_str().ok());

    // Get the target host from the environment variable
    let target_host_env = env::var("TARGET_HOST").ok();

    // Determine the target host with priority to the header
    let target_host = target_host_header.or(target_host_env.as_deref());

    let target_host = match target_host {
        Some(host) => host,
        None => return Ok(Response::builder()
            .status(400)
            .body("Target host must be specified via X-Target-Host header or TARGET_HOST environment variable".to_string())
            .expect("Failed to render response")),
    };

    // Extract scheme and host from the source URL
    let source_scheme = event
        .uri()
        .scheme()
        .map(|q| format!("{}://", q))
        .unwrap_or_default();
    let source_host = event.uri().host().unwrap_or_default();
    let source_port = event
        .uri()
        .port()
        .map(|q| format!(":{}", q))
        .unwrap_or_default();
    let source_host = format!("{}{}", source_host, source_port);

    // Check if the target host is the same as the source host to prevent recursion
    if target_host == source_host {
        return Ok(Response::builder()
            .status(400)
            .body(
                "Bad Request: Recursion detected, target host is the same as source host"
                    .to_string(),
            )
            .expect("Failed to render response"));
    }

    let source_path = event.uri().path();
    let source_query = event
        .uri()
        .query()
        .map(|q| format!("?{}", q))
        .unwrap_or_default();

    // Extract stage name from the request context and remove it from the request path
    let stage_name = match event.request_context() {
        lambda_http::request::RequestContext::ApiGatewayV2(context) => context.stage,
        lambda_http::request::RequestContext::ApiGatewayV1(context) => context.stage,
        lambda_http::request::RequestContext::WebSocket(context) => context.stage,
        _ => None,
    };

    // Remove the stage name from the request path
    let path_and_query = match stage_name {
        Some(stage) if source_path.starts_with(&format!("/{}", stage)) => {
            format!(
                "{}{}",
                source_path.trim_start_matches(&format!("/{}", stage)),
                source_query
            )
        }
        _ => format!("{}{}", source_path, source_query),
    };

    // Construct the target URL with inherited protocol
    let url = format!("{}{}{}", source_scheme, target_host, path_and_query);

    // Convert headers to reqwest format, excluding the X-Target-Host and X-API-Key headers
    let mut headers = reqwest::header::HeaderMap::new();
    for (key, value) in event.headers().iter() {
        if key == "X-Target-Host" || key == "X-API-Key" || key == "host" {
            continue;
        }
        let header_name = reqwest::header::HeaderName::from_bytes(key.as_ref()).unwrap();
        let header_value = reqwest::header::HeaderValue::from_str(value.to_str().unwrap()).unwrap();
        headers.insert(header_name, header_value);
    }

    info!("Output request body:\n{:?}\nHeaders:\n{:?}", &event.body(), &headers);

    // Make the request to the target host
    let response_result = match *event.method() {
        Method::GET => client.get(&url, headers).await,
        Method::POST => client.post(&url, headers, event.body().to_vec()).await,
        Method::PUT => client.put(&url, headers, event.body().to_vec()).await,
        Method::DELETE => client.delete(&url, headers, event.body().to_vec()).await,
        _ => {
            return Ok(Response::builder()
                .status(405)
                .body("Method Not Allowed".to_string())
                .expect("Failed to render response"))
        }
    };

    match response_result {
        Ok(response) => handle_response(response).await,
        Err(e) => Ok(Response::builder()
            .status(502)
            .body(format!("Error making request to target host: {}", e))
            .expect("Failed to render response")),
    }
}

/// The main entry point for the Lambda function.
///
/// This function initializes the Lambda runtime and sets the handler function.
///
/// # Returns
///
/// A `Result` containing an `Error` if the Lambda runtime fails to start.
#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .json()
        .with_max_level(tracing::Level::INFO)
        // this needs to be set to remove duplicated information in the log.
        .with_current_span(false)
        // disabling time is handy because CloudWatch will add the ingestion time.
        .without_time()
        // remove the name of the function from every log entry.
        .with_target(false)
        .init();

    let client = ClientBuilder::new().build().unwrap();

    lambda_http::run(service_fn(|event| function_handler(event, &client))).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::response::Builder;
    use lambda_http::http::{Method, Request};
    use lambda_http::request::RequestContext;
    use lambda_http::Body;
    use mockall::mock;
    use mockall::predicate::*;
    use reqwest::Response as ReqwestResponse;
    use std::collections::HashMap;

    mock! {
        pub MClient {}

        #[async_trait]
        impl HttpClient for MClient {
            async fn get(&self, url: &str, headers: reqwest::header::HeaderMap) -> Result<ReqwestResponse, reqwest::Error>;
            async fn post(&self, url: &str, headers: reqwest::header::HeaderMap, body: Vec<u8>) -> Result<ReqwestResponse, reqwest::Error>;
            async fn put(&self, url: &str, headers: reqwest::header::HeaderMap, body: Vec<u8>) -> Result<ReqwestResponse, reqwest::Error>;
            async fn delete(&self, url: &str, headers: reqwest::header::HeaderMap, body: Vec<u8>) -> Result<ReqwestResponse, reqwest::Error>;
        }
    }

    fn setup_env() {
        env::set_var("API_KEY", "test-api-key");
        env::set_var("TARGET_HOST", "localhost:1234");
    }
    fn clear_env() {
        env::remove_var("API_KEY");
        env::remove_var("TARGET_HOST");
    }

    fn mock_response(status: u16, body: &str, headers: HashMap<&str, &str>) -> ReqwestResponse {
        let response = Builder::new()
            .status(status)
            .body(body.to_string())
            .unwrap();

        let response = response.map(|body| body.into_bytes());

        let mut response = reqwest::Response::from(response);

        // Adjust headers
        for (key, value) in headers {
            response.headers_mut().insert(
                http::header::HeaderName::from_bytes(key.as_bytes()).unwrap(),
                http::header::HeaderValue::from_str(value).unwrap(),
            );
        }

        response
    }

    #[tokio::test]
    async fn test_authorization_failure() {
        setup_env();
        let mut client = MockMClient::new();
        // Add default expectation to avoid unexpected calls
        client.expect_get().never();

        let request = Request::default();

        let response = function_handler(request, &client)
            .await
            .expect("failed to handle request");
        assert_eq!(response.status(), 401);
        assert_eq!(response.body(), "Unauthorized");
        clear_env();
    }

    #[tokio::test]
    async fn test_missing_target_host() {
        clear_env();
        env::set_var("API_KEY", "test-api-key");
        let mut client = MockMClient::new();
        // Add default expectations to avoid unexpected calls
        client.expect_get().never();
        client.expect_post().never();
        client.expect_put().never();
        client.expect_delete().never();

        let request = Request::builder()
            .method(Method::GET)
            .header("X-API-Key", "test-api-key")
            .body(Body::Empty)
            .expect("failed to build request");

        let response = function_handler(request, &client).await.unwrap();
        assert_eq!(response.status(), 400);
        assert_eq!(response.body(), "Target host must be specified via X-Target-Host header or TARGET_HOST environment variable");
        clear_env();
    }

    #[tokio::test]
    async fn test_forwarding_get_request() {
        setup_env();
        let mut client = MockMClient::new();
        let mock_server_url = mockito::server_url();
        let mock_server_url2 = mock_server_url.clone();

        client
            .expect_get()
            .withf(move |url, _| url.starts_with(&format!("{}/test", &mock_server_url2)))
            .returning(|_, _| {
                let mut headers = HashMap::new();
                headers.insert("content-type", "text/plain");
                Ok(mock_response(200, "Hello, world!", headers))
            });

        let request = Request::builder()
            .method(Method::GET)
            .uri("/prod/test")
            .header("X-API-Key", "test-api-key")
            .header("X-Target-Host", mock_server_url)
            .body(Body::Empty)
            .expect("failed to build request");

        // Add request context with stage name
        let context = RequestContext::ApiGatewayV2(
            lambda_http::aws_lambda_events::apigw::ApiGatewayV2httpRequestContext {
                stage: Some("prod".into()),
                ..Default::default()
            },
        );

        let request = request.with_request_context(context);

        let response = function_handler(request, &client).await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.body(), "Hello, world!");
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "text/plain"
        );
        clear_env();
    }

    #[tokio::test]
    async fn test_recursion_prevention() {
        setup_env();
        let mut client = MockMClient::new();
        // Add default expectations to avoid unexpected calls
        client.expect_get().never();
        client.expect_post().never();
        client.expect_put().never();
        client.expect_delete().never();

        let request = Request::builder()
            .method(Method::GET)
            .uri("http://localhost:1234/test")
            .header("X-API-Key", "test-api-key")
            .header("X-Target-Host", "localhost:1234")
            .body(Body::Empty)
            .expect("failed to build request");

        let context = RequestContext::ApiGatewayV2(
            lambda_http::aws_lambda_events::apigw::ApiGatewayV2httpRequestContext {
                domain_name: Some("localhost:1234".to_string()),
                ..Default::default()
            },
        );

        let request = request.with_request_context(context);

        let response = function_handler(request, &client).await.unwrap();
        assert_eq!(response.status(), 400);
        assert_eq!(
            response.body(),
            "Bad Request: Recursion detected, target host is the same as source host"
        );
        clear_env();
    }

    #[tokio::test]
    async fn test_inheriting_url_scheme() {
        setup_env();
        let mut client = MockMClient::new();

        client
            .expect_get()
            .withf(|url, _| {
                // Check if the URL starts with "https://targethost.com"
                url.starts_with("https://targethost.com")
            })
            .returning(|_, _| {
                let mut headers = HashMap::new();
                headers.insert("content-type", "text/plain");
                Ok(mock_response(200, "Hello, world!", headers))
            });

        let request = Request::builder()
            .method(Method::GET)
            .uri("https://example.com/test")
            .header("X-API-Key", "test-api-key")
            .header("X-Target-Host", "targethost.com")
            .body(Body::Empty)
            .expect("failed to build request");

        let context = RequestContext::ApiGatewayV2(
            lambda_http::aws_lambda_events::apigw::ApiGatewayV2httpRequestContext {
                stage: Some("prod".into()),
                ..Default::default()
            },
        );

        let request = request.with_request_context(context);

        let response = function_handler(request, &client).await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.body(), "Hello, world!");
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "text/plain"
        );
        clear_env();
    }
}

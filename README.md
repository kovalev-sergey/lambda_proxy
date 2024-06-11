# lambda_proxy
A Rust-based AWS Lambda function that proxies REST API requests.

## AWS Lambda Proxy in Rust

This repository contains an AWS Lambda function written in Rust that acts as a proxy for REST APIs. The function forwards incoming HTTP requests to a specified target host. The target host can be set either via a header (`X-Target-Host`) or an environment variable (`TARGET_HOST`). The function also checks for an API key in the header (`X-API-Key`) to authorize requests and prevents recursive calls by ensuring the target host is not the same as the source host.

### Features

- **Authorization**: Checks for an `X-API-Key` header and compares it with the `API_KEY` environment variable. If the API keys do not match, it returns a `401 Unauthorized` response.
- **Target Host Configuration**: The target host for forwarding the request can be specified via the `X-Target-Host` header or the `TARGET_HOST` environment variable as host:port (`localhost:1234` or without port `example.com`).
- **HTTP Method Support**: Supports various HTTP methods (`GET`, `POST`, `PUT`, `DELETE`) and returns the response from the target host back to the client.

### Project Structure

- `src/main.rs`: The main Rust source file containing the Lambda function logic.
- `Cargo.toml`: The Cargo configuration file specifying dependencies and project metadata.
- `tests`: Contains unit tests for the Lambda function.

### Development
Build
```sh
cargo build --release --target aarch64-unknown-linux-musl && sam build
```
Deploy
```sh
sam deploy --guided
```

### Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue to discuss changes.

### License

This project is licensed under the MIT License. See the `LICENSE` file for details.



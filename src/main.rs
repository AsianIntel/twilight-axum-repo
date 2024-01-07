use axum::{
    body::Body,
    extract::Request,
    http::{StatusCode, Uri},
    middleware::map_request,
    response::{IntoResponse, Response},
    routing::post,
    Extension, Json, Router, ServiceExt,
};
use ed25519_dalek::{Verifier, VerifyingKey, PUBLIC_KEY_LENGTH};
use hex::FromHex;
use std::{error::Error, future::Future, pin::Pin, sync::Arc};
use tokio::net::TcpListener;
use tower::Layer;
use tower_http::{
    auth::{AsyncAuthorizeRequest, AsyncRequireAuthorizationLayer},
    trace::TraceLayer,
};
use twilight_http::Client as TwilightClient;
use twilight_model::{
    application::interaction::{Interaction, InteractionData, InteractionType},
    http::interaction::{InteractionResponse, InteractionResponseData, InteractionResponseType},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenvy::dotenv().unwrap();
    tracing_subscriber::fmt::init();

    let bot_token = std::env::var("BOT_TOKEN").expect("expected the bot token");
    let discord_public_key =
        std::env::var("DISCORD_PUBLIC_KEY").expect("Expected the discord public key");

    let twilight_http = Arc::new(TwilightClient::new(bot_token));
    let verifying_key = VerifyingKey::from_bytes(
        &<[u8; PUBLIC_KEY_LENGTH] as FromHex>::from_hex(discord_public_key).unwrap(),
    )
    .unwrap();

    let middleware = map_request(rewrite_request_uri);
    let app = Router::new()
        .route("/", post(pong))
        .route("/verify", post(verify_func))
        .layer(AsyncRequireAuthorizationLayer::new(WebhookAuth))
        .layer(Extension(Arc::new(verifying_key)))
        .layer(Extension(twilight_http))
        .layer(TraceLayer::new_for_http());
    let app_with_middleware = middleware.layer(app);
    let listener = TcpListener::bind("0.0.0.0:8000").await?;
    axum::serve(listener, app_with_middleware.into_make_service()).await?;

    Ok(())
}

async fn pong() -> Json<InteractionResponse> {
    Json(InteractionResponse {
        kind: InteractionResponseType::Pong,
        data: None,
    })
}

async fn rewrite_request_uri(req: Request) -> Request {
    let (mut parts, body) = req.into_parts();
    let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    let interaction = serde_json::from_slice::<Interaction>(&bytes).unwrap();

    if interaction.kind == InteractionType::ApplicationCommand {
        let data = match interaction.data {
            Some(InteractionData::ApplicationCommand(data)) => data,
            _ => unreachable!(),
        };
        let command_name = data.name;
        let mut uri_parts = parts.uri.into_parts();
        uri_parts.path_and_query = Some(format!("/{command_name}").parse().unwrap());
        let new_uri = Uri::from_parts(uri_parts).unwrap();
        parts.uri = new_uri;
    }

    let body = Body::from(bytes);
    let request = Request::from_parts(parts, body);
    request
}

#[derive(Clone)]
struct WebhookAuth;

impl AsyncAuthorizeRequest<Body> for WebhookAuth {
    type RequestBody = Body;
    type ResponseBody = Body;
    type Future =
        Pin<Box<dyn Future<Output = Result<Request<Body>, Response<Self::ResponseBody>>> + Send>>;

    fn authorize(&mut self, request: Request) -> Self::Future {
        Box::pin(async move {
            let verifying_key = request
                .extensions()
                .get::<Arc<VerifyingKey>>()
                .unwrap()
                .clone();

            let (parts, body) = request.into_parts();
            let Some(timestamp) = parts.headers.get("x-signature-timestamp") else {
                return Err(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::empty())
                    .unwrap());
            };
            let signature = match parts
                .headers
                .get("x-signature-ed25519")
                .and_then(|v| v.to_str().ok())
            {
                Some(h) => h.parse().unwrap(),
                None => {
                    return Err(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::empty())
                        .unwrap());
                }
            };

            let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
            if verifying_key
                .verify([timestamp.as_bytes(), &bytes].concat().as_ref(), &signature)
                .is_err()
            {
                return Err(Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(Body::empty())
                    .unwrap());
            }

            let body = Body::from(bytes);
            Ok(Request::from_parts(parts, body))
        })
    }
}

async fn verify_func(
    http: Extension<Arc<TwilightClient>>,
    interaction: Json<Interaction>,
) -> impl IntoResponse {
    tracing::info!("verify func");
    if let Err(err) = http
        .interaction(interaction.application_id)
        .create_response(
            interaction.id,
            &interaction.token,
            &InteractionResponse {
                kind: InteractionResponseType::ChannelMessageWithSource,
                data: Some(InteractionResponseData {
                    content: Some("test".into()),
                    ..Default::default()
                }),
            },
        )
        .await
    {
        tracing::error!(err = ?err);
    }

    let guild = http
        .guild(interaction.guild_id.unwrap())
        .await
        .unwrap()
        .model()
        .await
        .unwrap();
    tracing::info!(guild = ?guild);

    StatusCode::OK
}

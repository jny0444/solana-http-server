use axum::Json;
use axum::http::StatusCode;
use base64::{Engine as _, engine::general_purpose};
use serde_json::{Value, json};
use solana_sdk::{
    pubkey::Pubkey,
    signature::Signature,
    signer::{Signer, keypair::Keypair},
    system_instruction,
};
use spl_token::{
    ID as SPL_TOKEN_PROGRAM_ID,
    instruction::{initialize_mint, mint_to, transfer},
};
use std::str::FromStr;

use crate::models::{
    AccountMeta, CreateTokenRequest, CreateTokenResponse, ErrorResponse, GenerateKeypairResponse,
    InstructionPayload, MintTokenRequest, SendSolRequest, SendSolResponse, SendTokenRequest,
    SendTokenResponse, SignMessageRequest, SignMessageResponse, SimpleAccountMeta, SuccessResponse,
    VerifyMessageRequest, VerifyMessageResponse,
};

fn convert_account_meta_full(meta: &solana_program::instruction::AccountMeta) -> AccountMeta {
    AccountMeta {
        pubkey: meta.pubkey.to_string(),
        is_signer: meta.is_signer,
        is_writable: meta.is_writable,
    }
}

fn convert_account_meta_simple(
    meta: &solana_program::instruction::AccountMeta,
) -> SimpleAccountMeta {
    SimpleAccountMeta {
        pubkey: meta.pubkey.to_string(),
        is_signer: meta.is_signer,
    }
}

pub async fn post_keypair() -> Json<Value> {
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey().to_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();

    let response = SuccessResponse {
        success: true,
        data: GenerateKeypairResponse { pubkey, secret },
    };

    Json(json!(response))
}

pub async fn post_create_token(
    Json(payload): Json<CreateTokenRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if payload.decimals > u8::MAX as u64 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!(ErrorResponse { success: false, error: "Invalid decimals value".to_string() })),
        ));
    }
    if payload.mintAuthority.is_empty() || payload.mint.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!(ErrorResponse {
                success: false,
                error: "Missing required fields".to_string()
            })),
        ));
    }
    let mint_authority_pubkey = match Pubkey::from_str(&payload.mintAuthority) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!(ErrorResponse {
                    success: false,
                    error: "Invalid mintAuthority".to_string()
                })),
            ));
        }
    };

    let mint_pubkey = match Pubkey::from_str(&payload.mint) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!(ErrorResponse {
                    success: false,
                    error: "Invalid mint".to_string()
                })),
            ));
        }
    };

    let instruction = match initialize_mint(
        &SPL_TOKEN_PROGRAM_ID,
        &mint_pubkey,
        &mint_authority_pubkey,
        None,
        payload.decimals as u8,
    ) {
        Ok(inst) => inst,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!(ErrorResponse {
                    success: false,
                    error: "Failed to create instruction".to_string()
                })),
            ));
        }
    };

    let response = SuccessResponse {
        success: true,
        data: CreateTokenResponse {
            program_id: instruction.program_id.to_string(),
            accounts: instruction
                .accounts
                .into_iter()
                .map(|meta| convert_account_meta_full(&meta))
                .collect(),
            instruction_data: general_purpose::STANDARD.encode(instruction.data),
        },
    };

    Ok(Json(json!(response)))
}

pub async fn post_mint_token(
    Json(payload): Json<MintTokenRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if payload.amount == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!(ErrorResponse { success: false, error: "Invalid amount".to_string() })),
        ));
    }
    if payload.mint.is_empty() || payload.destination.is_empty() || payload.authority.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!(ErrorResponse {
                success: false,
                error: "Missing required fields".to_string()
            })),
        ));
    }

    let mint_pubkey = match Pubkey::from_str(&payload.mint) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!(ErrorResponse {
                    success: false,
                    error: "Invalid mint".to_string()
                })),
            ));
        }
    };

    let destination_pubkey = match Pubkey::from_str(&payload.destination) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!(ErrorResponse {
                    success: false,
                    error: "Invalid destination".to_string()
                })),
            ));
        }
    };

    let authority_pubkey = match Pubkey::from_str(&payload.authority) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!(ErrorResponse {
                    success: false,
                    error: "Invalid authority".to_string()
                })),
            ));
        }
    };

    let instruction = match mint_to(
        &SPL_TOKEN_PROGRAM_ID,
        &mint_pubkey,
        &destination_pubkey,
        &authority_pubkey,
        &[],
        payload.amount,
    ) {
        Ok(inst) => inst,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!(ErrorResponse {
                    success: false,
                    error: "Failed to create instruction".to_string()
                })),
            ));
        }
    };

    let response = SuccessResponse {
        success: true,
        data: InstructionPayload {
            program_id: instruction.program_id.to_string(),
            accounts: instruction
                .accounts
                .into_iter()
                .map(|meta| convert_account_meta_full(&meta))
                .collect(),
            instruction_data: general_purpose::STANDARD.encode(instruction.data),
        },
    };

    Ok(Json(json!(response)))
}

pub async fn post_sign_message(
    Json(payload): Json<SignMessageRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if payload.message.is_empty() || payload.secret.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!(ErrorResponse {
                success: false,
                error: "Missing required fields".to_string()
            })),
        ));
    }

    let keypair_bytes = match bs58::decode(&payload.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!(ErrorResponse {
                    success: false,
                    error: "Invalid secret".to_string()
                })),
            ));
        }
    };

    let keypair = match Keypair::from_bytes(&keypair_bytes) {
        Ok(kp) => kp,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!(ErrorResponse {
                    success: false,
                    error: "Invalid keypair".to_string()
                })),
            ));
        }
    };

    let message_bytes = payload.message.as_bytes();
    let signature = keypair.sign_message(message_bytes);

    let response = SuccessResponse {
        success: true,
        data: SignMessageResponse {
            signature: general_purpose::STANDARD.encode(signature.as_ref()),
            public_key: keypair.pubkey().to_string(),
            message: payload.message,
        },
    };

    Ok(Json(json!(response)))
}

pub async fn post_verify_message(
    Json(payload): Json<VerifyMessageRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if payload.message.is_empty() || payload.signature.is_empty() || payload.pubkey.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!(ErrorResponse {
                success: false,
                error: "Missing required fields".to_string()
            })),
        ));
    }

    let pubkey = match Pubkey::from_str(&payload.pubkey) {
        Ok(pk) => pk,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!(ErrorResponse {
                    success: false,
                    error: "Invalid pubkey".to_string()
                })),
            ));
        }
    };

    let signature_bytes = match general_purpose::STANDARD.decode(&payload.signature) {
        Ok(bytes) => bytes,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!(ErrorResponse {
                    success: false,
                    error: "Invalid signature".to_string()
                })),
            ));
        }
    };

    let signature = match Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!(ErrorResponse {
                    success: false,
                    error: "Invalid signature".to_string()
                })),
            ));
        }
    };

    let message_bytes = payload.message.as_bytes();
    let valid = signature.verify(&pubkey.as_ref(), message_bytes);

    let response = SuccessResponse {
        success: true,
        data: VerifyMessageResponse {
            valid,
            message: payload.message,
            pubkey: payload.pubkey,
        },
    };

    Ok(Json(json!(response)))
}

pub async fn post_sol_send(
    Json(payload): Json<SendSolRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if payload.from.is_empty() || payload.to.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!(ErrorResponse {
                success: false,
                error: "Missing required fields".to_string()
            })),
        ));
    }
    if payload.lamports == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!(ErrorResponse {
                success: false,
                error: "Invalid lamports amount".to_string()
            })),
        ));
    }
    if payload.from == payload.to {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!(ErrorResponse { success: false, error: "Source and destination must differ".to_string() })),
        ));
    }

    let from_pubkey = match Pubkey::from_str(&payload.from) {
        Ok(pk) => pk,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!(ErrorResponse {
                    success: false,
                    error: "Invalid from pubkey".to_string()
                })),
            ));
        }
    };

    let to_pubkey = match Pubkey::from_str(&payload.to) {
        Ok(pk) => pk,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!(ErrorResponse {
                    success: false,
                    error: "Invalid to pubkey".to_string()
                })),
            ));
        }
    };

    let instruction = system_instruction::transfer(&from_pubkey, &to_pubkey, payload.lamports);

    let response = SuccessResponse {
        success: true,
        data: SendSolResponse {
            program_id: instruction.program_id.to_string(),
            accounts: instruction
                .accounts
                .into_iter()
                .map(|meta| meta.pubkey.to_string())
                .collect(),
            instruction_data: general_purpose::STANDARD.encode(instruction.data),
        },
    };

    Ok(Json(json!(response)))
}

pub async fn post_token_send(
    Json(payload): Json<SendTokenRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if payload.destination.is_empty() || payload.mint.is_empty() || payload.owner.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!(ErrorResponse {
                success: false,
                error: "Missing required fields".to_string()
            })),
        ));
    }
    if payload.amount == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!(ErrorResponse {
                success: false,
                error: "Invalid amount".to_string()
            })),
        ));
    }
    if payload.owner == payload.destination {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!(ErrorResponse { success: false, error: "Owner and destination must differ".to_string() })),
        ));
    }

    let _mint_pubkey = match Pubkey::from_str(&payload.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!(ErrorResponse {
                    success: false,
                    error: "Invalid mint".to_string()
                })),
            ));
        }
    };

    let owner_pubkey = match Pubkey::from_str(&payload.owner) {
        Ok(pk) => pk,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!(ErrorResponse {
                    success: false,
                    error: "Invalid owner".to_string()
                })),
            ));
        }
    };

    let destination_pubkey = match Pubkey::from_str(&payload.destination) {
        Ok(pk) => pk,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!(ErrorResponse {
                    success: false,
                    error: "Invalid destination".to_string()
                })),
            ));
        }
    };

    let instruction = match transfer(
        &SPL_TOKEN_PROGRAM_ID,
        &owner_pubkey,
        &destination_pubkey,
        &owner_pubkey,
        &[],
        payload.amount,
    ) {
        Ok(inst) => inst,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!(ErrorResponse {
                    success: false,
                    error: "Failed to create instruction".to_string()
                })),
            ));
        }
    };

    let response = SuccessResponse {
        success: true,
        data: SendTokenResponse {
            program_id: instruction.program_id.to_string(),
            accounts: instruction
                .accounts
                .into_iter()
                .map(|meta| convert_account_meta_simple(&meta))
                .collect(),
            instruction_data: general_purpose::STANDARD.encode(instruction.data),
        },
    };

    Ok(Json(json!(response)))
}

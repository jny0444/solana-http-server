use axum::Json;
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

pub async fn post_create_token(Json(payload): Json<CreateTokenRequest>) -> Json<serde_json::Value> {
    let mint_authority_pubkey = match Pubkey::from_str(&payload.mintAuthority) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Json(json!(ErrorResponse {
                success: false,
                error: "Description of error".to_string(),
            }));
        }
    };

    let mint_pubkey = match Pubkey::from_str(&payload.mint) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Json(json!(ErrorResponse {
                success: false,
                error: "Description of error".to_string(),
            }));
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
            return Json(json!(ErrorResponse {
                success: false,
                error: "Description of error".to_string(),
            }));
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

    Json(json!(response))
}

pub async fn post_mint_token(Json(payload): Json<MintTokenRequest>) -> Json<serde_json::Value> {
    let mint_pubkey = match Pubkey::from_str(&payload.mint) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Json(json!(ErrorResponse {
                success: false,
                error: "Description of error".to_string(),
            }));
        }
    };

    let destination_pubkey = match Pubkey::from_str(&payload.destination) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Json(json!(ErrorResponse {
                success: false,
                error: "Description of error".to_string(),
            }));
        }
    };

    let authority_pubkey = match Pubkey::from_str(&payload.authority) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Json(json!(ErrorResponse {
                success: false,
                error: "Description of error".to_string(),
            }));
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
            return Json(json!(ErrorResponse {
                success: false,
                error: "Description of error".to_string(),
            }));
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

    Json(json!(response))
}

pub async fn post_sign_message(Json(payload): Json<SignMessageRequest>) -> Json<serde_json::Value> {
    let keypair_bytes = match bs58::decode(&payload.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            return Json(json!(ErrorResponse {
                success: false,
                error: "Description of error".to_string(),
            }));
        }
    };

    let keypair = match Keypair::from_bytes(&keypair_bytes) {
        Ok(kp) => kp,
        Err(_) => {
            return Json(json!(ErrorResponse {
                success: false,
                error: "Description of error".to_string(),
            }));
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

    Json(json!(response))
}

pub async fn post_verify_message(
    Json(payload): Json<VerifyMessageRequest>,
) -> Json<serde_json::Value> {
    let pubkey = match Pubkey::from_str(&payload.pubkey) {
        Ok(pk) => pk,
        Err(_) => {
            return Json(json!(ErrorResponse {
                success: false,
                error: "Description of error".to_string(),
            }));
        }
    };

    let signature_bytes = match general_purpose::STANDARD.decode(&payload.signature) {
        Ok(bytes) => bytes,
        Err(_) => {
            return Json(json!(ErrorResponse {
                success: false,
                error: "Description of error".to_string(),
            }));
        }
    };

    let signature = match Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => {
            return Json(json!(ErrorResponse {
                success: false,
                error: "Description of error".to_string(),
            }));
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

    Json(json!(response))
}

pub async fn post_sol_send(Json(payload): Json<SendSolRequest>) -> Json<serde_json::Value> {
    let from_pubkey = match Pubkey::from_str(&payload.from) {
        Ok(pk) => pk,
        Err(_) => {
            return Json(json!(ErrorResponse {
                success: false,
                error: "Description of error".to_string(),
            }));
        }
    };

    let to_pubkey = match Pubkey::from_str(&payload.to) {
        Ok(pk) => pk,
        Err(_) => {
            return Json(json!(ErrorResponse {
                success: false,
                error: "Description of error".to_string(),
            }));
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

    Json(json!(response))
}

pub async fn post_token_send(Json(payload): Json<SendTokenRequest>) -> Json<serde_json::Value> {
    let _mint_pubkey = match Pubkey::from_str(&payload.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return Json(json!(ErrorResponse {
                success: false,
                error: "Description of error".to_string(),
            }));
        }
    };

    let owner_pubkey = match Pubkey::from_str(&payload.owner) {
        Ok(pk) => pk,
        Err(_) => {
            return Json(json!(ErrorResponse {
                success: false,
                error: "Description of error".to_string(),
            }));
        }
    };

    let destination_pubkey = match Pubkey::from_str(&payload.destination) {
        Ok(pk) => pk,
        Err(_) => {
            return Json(json!(ErrorResponse {
                success: false,
                error: "Description of error".to_string(),
            }));
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
            return Json(json!(ErrorResponse {
                success: false,
                error: "Description of error".to_string(),
            }));
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

    Json(json!(response))
}

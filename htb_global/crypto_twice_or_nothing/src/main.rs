use sha2::{Sha256, Digest};
use crypto_bigint::{U256, Encoding};
use rand::{rng, prelude::*};
use std::io::{self, Write};
use hex;

const N: usize = 256;
const BURN_LIMIT: u8 = 5;
const TARGET_MSG: &str = "d9_netadmin";

#[derive(Debug,Clone)]
struct AuthKey {
    key_pairs: [(U256, U256); N]
}
#[derive(Debug,Clone)]
struct AuthPub {
    commitments: [([u8; N/8], [u8; N/8]); N]
}

fn to_bits(n: U256) -> [bool; N] {
    std::array::from_fn(|i| n.bit_vartime((N - 1 - i) as u32))
}

fn get_random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rng().fill_bytes(&mut buf);
    buf
}

fn hash_digest(s: &[u8]) -> [u8; N/8] {
    Sha256::digest(s).into()
}

fn issue_credentials() -> (AuthKey, AuthPub) {
    let key_pairs = std::array::from_fn(|_| {
        (
            U256::from_be_slice(&get_random_bytes(N/8)),
            U256::from_be_slice(&get_random_bytes(N/8))
        )
    });
    let commitments = key_pairs.iter().map(|(s0, s1)| {
                                (hash_digest(&s0.to_be_bytes()), hash_digest(&s1.to_be_bytes()))
                            })
                            .collect::<Vec<_>>()
                            .try_into()
                            .unwrap();
    (AuthKey { key_pairs }, AuthPub { commitments })
}

fn issue_token(m: &[u8], auth_key: AuthKey) -> [U256; N] {
    let message_hash = U256::from_be_bytes(hash_digest(m).into());
    let hash_bits = to_bits(message_hash);
    assert!(hash_bits.len() == auth_key.key_pairs.len(), "ERROR: The number of hash bits and the size of the secret key must match.");
    std::array::from_fn(|i| {
        let (zero, one) = auth_key.key_pairs[i];
        if hash_bits[i] { one } else { zero }
    })
}

fn validate_token(m: &[u8], token: [U256; N], auth_pub: AuthPub) -> bool {
    let message_hash = U256::from_be_bytes(hash_digest(m).into());
    let hash_bits = to_bits(message_hash);
    assert!(hash_bits.len() == auth_pub.commitments.len(), "ERROR: The number of hash bits and the size of the public key must match.");
    let chosen_pk = std::array::from_fn(|i| {
        let (zero, one) = auth_pub.commitments[i];
        if hash_bits[i] { U256::from_be_slice(&one) } else { U256::from_be_slice(&zero) }
    });
    let hashed_token: [U256; N] = token.map(|s| { U256::from_be_bytes(hash_digest(&s.to_be_bytes()).into()) });
    chosen_pk == hashed_token
}

fn main() {
    let (auth_key, auth_pub) = issue_credentials();
    let mut issue_count: u8 = 0;
    println!("--- D9 Hardened Authentication Gateway ---");
    println!("Issuing access tokens for Korvia's infrastructure nodes. Use wisely.");
    loop {
        let mut choice = String::new();
        println!("1. Issue authentication token");
        println!("2. Validate authentication token");
        println!("3. Abort session");
        print!("> ");

        io::stdout().flush().unwrap();
        if io::stdin().read_line(&mut choice).is_err() { break; }

        match choice.as_str().trim() {
            "1" => {
                if issue_count > BURN_LIMIT {
                    println!("[BURNOUT] Maximum token issues reached. Key material exhausted.");
                    break;
                }
                print!("Enter credential payload in hex: ");
                io::stdout().flush().unwrap();
        
                let mut input = String::new();
                if io::stdin().read_line(&mut input).is_err() { break; }
        
                let msg = input.trim();
                if msg.is_empty() { continue; }
        
                match hex::decode(msg) {
                    Ok(msg) if msg.windows(TARGET_MSG.len()).any(|w| w == TARGET_MSG.as_bytes()) => {
                        println!("ERROR: [REJECTED] Target admin token is restricted.")
                    },
                    Ok(msg) => {
                        let token = issue_token(&msg, auth_key.clone());
                        println!("Token issued: {:?}", token);
                        issue_count += 1;
                    }
                    Err(_) => println!("ERROR: Invalid hex input!"),
                }
            },
            "2" => {
                let mut msg_input = String::new();
                let mut sig_input = String::new();

                print!("Enter admin message to validate: ");
                io::stdout().flush().unwrap();
                io::stdin().read_line(&mut msg_input).expect("ERROR: Failed to read message");
                let msg = msg_input.trim();

                print!("Enter token segments (comma-separated hex): ");
                io::stdout().flush().unwrap();
                io::stdin().read_line(&mut sig_input).expect("ERROR: Failed to read signature");

                let token_array: [U256; N]= sig_input.trim().split(",")
                    .map(|s| U256::from_be_hex(s))
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap_or_else(|_| { panic!("ERROR: Expected exactly 256 parts!") });
                let verified = validate_token(msg.as_bytes(), token_array, auth_pub.clone());
                if verified {
                    if msg == TARGET_MSG {
                        let flag = std::fs::read_to_string("flag.txt")
                            .unwrap_or_else(|_| "HTB{f4ke_fl4g_f0r_t3st1ng}".to_string());
                        println!("{}", flag);
                    } else {
                        println!("[AUTH GRANTED] Token validated. Access permitted.");
                    }
                } else {
                    println!("ERROR: [AUTH FAILED] Invalid token. Intrusion logged.");
                }
            },
            "3" => {
                println!("Session terminated.");
                break;
            }
            _ => println!("Unknown option!"),
        
        }
    }
}

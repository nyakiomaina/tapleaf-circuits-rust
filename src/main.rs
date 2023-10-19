extern crate bitcoin;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use sha2::{Sha256, Digest};
use tokio;
use std::collections::VecDeque;
use bitcoin::{Address, PublicKey, Network};
use bitcoin::blockdata::script;
use std::str::FromStr;
use hex;

struct TaprootCircuit {
    wire_settings: HashMap<String, Vec<String>>,
    wire_hashes: HashMap<String, Vec<String>>,
    operations_array: Vec<Vec<String>>,
    initial_commitment_preimages: Vec<Vec<String>>,
}

#[derive(Debug, Clone)]
struct BitCommitmentAddress {
    script: Vec<String>,
}

#[derive(Debug, Clone)]
struct AntiContradictionAddress {
    script: Vec<String>, 
}

struct TapScript {
    // Dummy implementations. 
    pub fn encode_script(script: Vec<&str>) -> Vec<u8> { vec![] }
    pub fn get_pub_key(pubkey: &str, params: &TapScriptParams) -> (String, String) { (String::new(), String::new()) }
}

struct TapScriptAddress {
    // Dummy implementation
    pub fn p2tr_from_pub_key(pub_key: &str) -> String { String::new() }
}

struct TapScriptParams {
    tree: Vec<Vec<u8>>,
    target: Vec<u8>,
}

#[tokio::main]
async fn main() {
    // Sample call
    let address = generate_bit_commitment_address(
        "",
        "",
        &vec![(String::from("hash1a"), String::from("hash1b"))],
        &vec![(String::from("hash2a"), String::from("hash2b"))],
        Network::Bitcoin,

        let pubkey = "";
        let vickys_key = "";
        generate_challenge_address(pubkey, vickys_key);
    );
    println!("{:?}", address);
}

fn sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    hex::decode(hex).expect("Decoding failed")
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn get_rand(size: usize) -> String {
    let random_bytes: Vec<u8> = (0..size).map(|_| rand::random::<u8>()).collect();
    bytes_to_hex(&random_bytes)
}

fn and(a: bool, b: bool) -> bool {
    a && b
}

fn xor(a: bool, b: bool) -> bool {
    a ^ b
}

fn inv(a: bool) -> bool {
    !a
}

fn remove_duplicates<T: std::cmp::PartialEq + Clone>(arr: Vec<T>) -> Vec<T> {
    arr.into_iter().unique().collect()
}

fn compare_tapleaves(preimage: &str, challenge_scripts: &Vec<Vec<String>>) -> Vec<usize> {
    let mut scripts_this_preimage_is_referenced_in = Vec::new();
    let hash = sha256(&hex_to_bytes(preimage));
    
    for (index, script) in challenge_scripts.iter().enumerate() {
        for element in script {
            if element == &hash {
                scripts_this_preimage_is_referenced_in.push(index);
            }
        }
    }
    
    scripts_this_preimage_is_referenced_in
}

fn discard_unused_preimages(preimages_from_paul: &mut Vec<String>, challenge_scripts: &Vec<Vec<String>>) {
    let mut i = 0;
    while i < preimages_from_paul.len() {
        let tapleaves_it_is_in = compare_tapleaves(&preimages_from_paul[i], challenge_scripts);
        if tapleaves_it_is_in.is_empty() {
            preimages_from_paul.remove(i);
        } else {
            i += 1;
        }
    }
}
fn op_not(input_preimage: &str, expected_input_hash: &str, input_value: bool, output_preimage: &str, expected_output_hash: &str, output_value: bool) -> String {
    let real_input_hash = sha256(&hex_to_bytes(input_preimage));
    if real_input_hash != expected_input_hash {
        return "you cannot spend with this tapleaf".to_string();
    }
    let real_output_hash = sha256(&hex_to_bytes(output_preimage));
    if real_output_hash != expected_output_hash {
        return "you cannot spend with this tapleaf".to_string();
    }
    if !input_value == output_value {
        return format!("you can spend with these preimages: {} as the input preimage and {} as the output preimage", input_preimage, output_preimage);
    }
    "you cannot spend with this tapleaf".to_string()
}

fn op_booland(first_input_preimage: &str, first_expected_input_hash: &str, first_input_value: bool, second_input_preimage: &str, second_expected_input_hash: &str, second_input_value: bool, output_preimage: &str, expected_output_hash: &str, output_value: bool) -> String {
    let real_first_input_hash = sha256(&hex_to_bytes(first_input_preimage));
    if real_first_input_hash != first_expected_input_hash {
        return "you cannot spend with this tapleaf".to_string();
    }
    let real_second_input_hash = sha256(&hex_to_bytes(second_input_preimage));
    if real_second_input_hash != second_expected_input_hash {
        return "you cannot spend with this tapleaf".to_string();
    }
    let real_output_hash = sha256(&hex_to_bytes(output_preimage));
    if real_output_hash != expected_output_hash {
        return "you cannot spend with this tapleaf".to_string();
    }
    if first_input_value && second_input_value == output_value {
        return format!("you can spend with these preimages: {} as the first input preimage, {} as the second, and {} as the output preimage", first_input_preimage, second_input_preimage, output_preimage);
    }
    "you cannot spend with this tapleaf".to_string()
}

fn op_xor(first_input_preimage: &str, first_expected_input_hash: &str, first_input_value: bool, second_input_preimage: &str, second_expected_input_hash: &str, second_input_value: bool, output_preimage: &str, expected_output_hash: &str, output_value: bool) -> String {
    let real_first_input_hash = sha256(&hex_to_bytes(first_input_preimage));
    if real_first_input_hash != first_expected_input_hash {
        return "you cannot spend with this tapleaf".to_string();
    }
    let real_second_input_hash = sha256(&hex_to_bytes(second_input_preimage));
    if real_second_input_hash != second_expected_input_hash {
        return "you cannot spend with this tapleaf".to_string();
    }
    let real_output_hash = sha256(&hex_to_bytes(output_preimage));
    if real_output_hash != expected_output_hash {
        return "you cannot spend with this tapleaf".to_string();
    }
    if first_input_value ^ second_input_value == output_value {
        return format!("you can spend with these preimages: {} as the first input preimage, {} as the second, and {} as the output preimage", first_input_preimage, second_input_preimage, output_preimage);
    }
    "you cannot spend with this tapleaf".to_string()
}

fn make_bristol_array(arrprep: &str) -> (Vec<String>, u32, u32, u32) {
    let mut arr: Vec<String> = arrprep.split('\n').map(|s| s.trim().to_string()).collect();

    arr = arr.iter().map(|entry| {
        if entry.starts_with(" ") {
            entry[1..].to_string()
        } else {
            entry.clone()
        }
    }).collect();

    if arr[0].is_empty() {
        arr.remove(0);
    }
    if arr.last().map_or(false, |s| s.is_empty()) {
        arr.pop();
    }
    if arr.get(3).is_some() {
        // to add error handling
        println!("Oops, you entered an invalid bristol circuit! Try again with the whole document, including the first three lines that define the number of gates, number of input bits, and number of output bits.");
    }
    let number_of_preimages_to_expect = arr[0].split_whitespace().nth(1).unwrap_or("0").parse::<u32>().unwrap_or(0);
    let number_of_inputs = arr[1].split_whitespace().nth(1).unwrap_or("0").parse::<u32>().unwrap_or(0);
    let number_of_outputs = arr[2].split_whitespace().nth(1).unwrap_or("0").parse::<u32>().unwrap_or(0);

    arr.drain(0..4);

    (arr, number_of_preimages_to_expect, number_of_inputs, number_of_outputs)
}

async fn set_operations_array(
    arr: &mut Vec<String>,
    wire_settings: &mut HashMap<String, Vec<String>>,
    wire_hashes: &mut HashMap<String, Vec<String>>,
    operations_array: &mut Vec<Vec<String>>,
    get_rand: &dyn Fn(u32) -> String,
    sha256: &dyn Fn(Vec<u8>) -> String,
    hex_to_bytes: &dyn Fn(String) -> Vec<u8>,
) {
    for index in 0..arr.len() {
        let gate: Vec<String> = arr[index].split_whitespace().map(|s| s.to_string()).collect();

        match gate.last().unwrap_or(&"".to_string()).as_str() {
            "INV" => {
                let key = gate[2].clone();

                let input_preimages = wire_settings.entry(key.clone())
                    .or_insert_with(|| vec![get_rand(32), get_rand(32)]).clone();

                let output_preimages = vec![get_rand(32), get_rand(32)];

                let input_hashes = vec![
                    sha256(hex_to_bytes(input_preimages[0].clone())),
                    sha256(hex_to_bytes(input_preimages[1].clone()))
                ];

                wire_hashes.insert(key, input_hashes.clone());

                let output_hashes = vec![
                    sha256(hex_to_bytes(output_preimages[0].clone())),
                    sha256(hex_to_bytes(output_preimages[1].clone()))
                ];

                wire_settings.insert(gate[3].clone(), output_preimages.clone());
                wire_hashes.insert(gate[3].clone(), output_hashes.clone());

                operations_array.push(vec![
                    "INV".to_string(),
                    format!("input_preimages {} {}", input_preimages[0], input_preimages[1]),
                    format!("output_preimages {} {}", output_preimages[0], output_preimages[1]),
                    format!("input_hashes {} {}", input_hashes[0], input_hashes[1]),
                    format!("output_hashes {} {}", output_hashes[0], output_hashes[1]),
                    format!("var w_{} = INV( wires[ {} ] )", gate[3], gate[2])
                ]);
            },

            "AND" => {
                let first_key = gate[2].clone();
                let second_key = gate[3].clone();

                let first_input_preimages = wire_settings.entry(first_key.clone())
                    .or_insert_with(|| vec![get_rand(32), get_rand(32)]).clone();

                let second_input_preimages = wire_settings.entry(second_key.clone())
                    .or_insert_with(|| vec![get_rand(32), get_rand(32)]).clone();

                let first_input_hashes = vec![
                    sha256(hex_to_bytes(first_input_preimages[0].clone())),
                    sha256(hex_to_bytes(first_input_preimages[1].clone()))
                ];
                let second_input_hashes = vec![
                    sha256(hex_to_bytes(second_input_preimages[0].clone())),
                    sha256(hex_to_bytes(second_input_preimages[1].clone()))
                ];

                let output_preimages = vec![get_rand(32), get_rand(32)];
                let output_hashes = vec![
                    sha256(hex_to_bytes(output_preimages[0].clone())),
                    sha256(hex_to_bytes(output_preimages[1].clone()))
                ];

                wire_hashes.insert(first_key, first_input_hashes.clone());
                wire_hashes.insert(second_key, second_input_hashes.clone());
                wire_settings.insert(gate[4].clone(), output_preimages.clone());
                wire_hashes.insert(gate[4].clone(), output_hashes.clone());

                operations_array.push(vec![
                    "AND".to_string(),
                    format!("first_input_preimages {} {}", first_input_preimages[0], first_input_preimages[1]),
                    format!("second_input_preimages {} {}", second_input_preimages[0], second_input_preimages[1]),
                    format!("output_preimages {} {}", output_preimages[0], output_preimages[1]),
                    format!("first_input_hashes {} {}", first_input_hashes[0], first_input_hashes[1]),
                    format!("second_input_hashes {} {}", second_input_hashes[0], second_input_hashes[1]),
                    format!("output_hashes {} {}", output_hashes[0], output_hashes[1]),
                    format!("var w_{} = AND( wires[ {} ], wires[ {} ] )", gate[4], gate[2], gate[3])
                ]);
            },

            "XOR" => {
                let (first_key, second_key, output_key) = (gate[2].clone(), gate[3].clone(), gate[4].clone());

                let first_input_preimages = wire_settings.entry(first_key.clone())
                    .or_insert_with(|| vec![get_rand(32), get_rand(32)]).clone();

                let second_input_preimages = wire_settings.entry(second_key.clone())
                    .or_insert_with(|| vec![get_rand(32), get_rand(32)]).clone();

                let first_input_hashes = vec![
                    sha256(hex_to_bytes(first_input_preimages[0].clone())),
                    sha256(hex_to_bytes(first_input_preimages[1].clone()))
                ];
                let second_input_hashes = vec![
                    sha256(hex_to_bytes(second_input_preimages[0].clone())),
                    sha256(hex_to_bytes(second_input_preimages[1].clone()))
                ];

                let output_preimages = vec![get_rand(32), get_rand(32)];
                let output_hashes = vec![
                    sha256(hex_to_bytes(output_preimages[0].clone())),
                    sha256(hex_to_bytes(output_preimages[1].clone()))
                ];

                wire_hashes.insert(first_key, first_input_hashes.clone());
                wire_hashes.insert(second_key, second_input_hashes.clone());
                wire_settings.insert(output_key.clone(), output_preimages.clone());
                wire_hashes.insert(output_key, output_hashes.clone());

                operations_array.push(vec![
                    "XOR".to_string(),
                    format!("first_input_preimages {} {}", first_input_preimages[0], first_input_preimages[1]),
                    format!("second_input_preimages {} {}", second_input_preimages[0], second_input_preimages[1]),
                    format!("output_preimages {} {}", output_preimages[0], output_preimages[1]),
                    format!("first_input_hashes {} {}", first_input_hashes[0], first_input_hashes[1]),
                    format!("second_input_hashes {} {}", second_input_hashes[0], second_input_hashes[1]),
                    format!("output_hashes {} {}", output_hashes[0], output_hashes[1]),
                    format!("var w_{} = XOR( wires[ {} ], wires[ {} ] )", gate[4], gate[2], gate[3])
                ]);
            },

            _ => {}
        }
    }
}

async fn generate_bit_commitments(
    wire_settings: &HashMap<String, Vec<String>>,
    initial_commitment_preimages: &mut Vec<Vec<String>>,
    initial_commitment_hashes: &mut Vec<(Vec<u8>, Vec<u8>)>,
) {
    for i in 0..64 {
        let key = i.to_string();
        if let Some(preimages) = wire_settings.get(&key) {
            initial_commitment_preimages.push(preimages.clone());

            let hash_0 = sha256(hex_to_bytes(preimages[0].clone())).await;
            let hash_1 = sha256(hex_to_bytes(preimages[1].clone())).await;
            initial_commitment_hashes.push((hash_0, hash_1));
        }
    }
}

fn save_data(data: &[u8], file_name: &str) {
    std::fs::write(file_name, data).expect("Failed to write to file");
}

fn generate_bit_commitment_address(pubkey: &str, vickys_key: &str, network: &str, initial_commitment_hashes: Vec<(&str, &str)>, subsequent_commitment_hashes: Vec<(&str, &str)>) -> String {
    let leaf1 = vec![
        "OP_10",
        "OP_CHECKSEQUENCEVERIFY",
        "OP_DROP",
        vickys_key,
        "OP_CHECKSIG"
    ];

    let leaf2 = vec![
        "OP_0",
        pubkey,
        "OP_CHECKSIGADD",
        vickys_key,
        "OP_CHECKSIGADD",
        "OP_2",
        "OP_EQUAL"
    ];

    let mut bit_commitment_template = "
        OP_SHA256
        INSERT_16_BYTE_HERE
        OP_EQUAL
        OP_SWAP
        OP_SHA256
        INSERT_17_BYTE_HERE
        OP_EQUAL
        OP_BOOLOR
        OP_VERIFY
    ".to_string();

    let mut bit_commitment_script = String::new();

    for hash_pair in initial_commitment_hashes.iter().chain(&subsequent_commitment_hashes) {
        bit_commitment_script += &bit_commitment_template.replace("INSERT_16_BYTE_HERE", hash_pair.0).replace("INSERT_17_BYTE_HERE", hash_pair.1);
    }

    bit_commitment_script += &format!("
        {}
        OP_CHECKSIG
    ", pubkey);

    let bit_commitment_script_array: Vec<&str> = bit_commitment_script.split_whitespace().collect();
    let leaf3: Vec<&str> = bit_commitment_script_array[1..bit_commitment_script_array.len()-1].to_vec();

    let scripts = vec![leaf1, leaf2, leaf3];
    let tree: Vec<Vec<u8>> = scripts.iter().map(|s| TapScript::encode_script(s.to_vec())).collect();

    let selected_script = &scripts[2];
    let bit_commitment_script = selected_script.clone();
    let commitment_to_anywhere_else_script = &scripts[1];

    let bit_commitment_tapleaf = TapScript::encode_script(bit_commitment_script);
    let commitment_to_anywhere_else_tapleaf = TapScript::encode_script(commitment_to_anywhere_else_script.to_vec());

    let target = TapScript::encode_script(selected_script.to_vec());

    let (tpubkey, cblock) = TapScript::get_pub_key(&"ab".repeat(32), &TapScriptParams { tree: tree.clone(), target });
    let bit_commitment_tpubkey = tpubkey;
    let bit_commitment_cblock = cblock;

    let (tpubkey, alt_cblock) = TapScript::get_pub_key(&"ab".repeat(32), &TapScriptParams { tree, target: commitment_to_anywhere_else_tapleaf });
    let commitment_to_anywhere_else_cblock = alt_cblock;

    let bit_commitment_address = TapScriptAddress::p2tr_from_pub_key(&bit_commitment_tpubkey);

    bit_commitment_address
}

fn generate_challenge_address(pubkey: &str, vickys_key: &str) {
    let mut templates: HashMap<&str, String> = HashMap::new();

    let op_not_template = format!(r#"
        OP_TOALTSTACK
        OP_SHA256
        INSERT_INPUT_HERE
        OP_EQUALVERIFY
        {}
        OP_NOT
        OP_FROMALTSTACK
        OP_SHA256
        INSERT_OUTPUT_HERE
        OP_EQUALVERIFY
        {}
        OP_NUMNOTEQUAL
        OP_VERIFY
        {}
        OP_CHECKSIG
    "#, "{}", "{}", vickys_key);

    let op_booland_template = format!(r#"
        OP_TOALTSTACK
        OP_SHA256
        INSERT_FIRST_INPUT_HERE
        OP_EQUALVERIFY
        {}
        OP_SWAP
        OP_SHA256
        INSERT_SECOND_INPUT_HERE
        OP_EQUALVERIFY
        {}
        OP_BOOLAND
        OP_FROMALTSTACK
        OP_SHA256
        INSERT_OUTPUT_HERE
        OP_EQUALVERIFY
        {}
        OP_NUMNOTEQUAL
        OP_VERIFY
        {}
        OP_CHECKSIG
    "#, "{}", "{}", "{}", vickys_key);

    let op_xor_template = format!(r#"
        OP_TOALTSTACK
        OP_SHA256
        INSERT_FIRST_INPUT_HERE
        OP_EQUALVERIFY
        {}
        OP_SWAP
        OP_SHA256
        INSERT_SECOND_INPUT_HERE
        OP_EQUALVERIFY
        {}
        OP_NUMNOTEQUAL
        OP_FROMALTSTACK
        OP_SHA256
        INSERT_OUTPUT_HERE
        OP_EQUALVERIFY
        {}
        OP_NUMNOTEQUAL
        OP_VERIFY
        {}
        OP_CHECKSIG
    "#, "{}", "{}", "{}", vickys_key);

    let op_not_inputs = vec!["0", "1"];
    let op_booland_inputs = vec!["00", "01", "10", "11"];
    let op_xor_inputs = vec!["000", "001", "010", "011", "100", "101", "110", "111"];

    for input in op_not_inputs {
        let template_name = format!("OP_NOT_{}", input);
        let input_value = if input == "0" { "OP_0" } else { "OP_1" };
        let output_value = if input.chars().last().unwrap() == '0' { "OP_0" } else { "OP_1" };
        let filled_template = op_not_template.replace("{}", input_value).replace("INSERT_INPUT_HERE", input_value).replace("INSERT_OUTPUT_HERE", output_value);
        templates.insert(&template_name, filled_template);
    }

    for input in op_booland_inputs {
        let template_name = format!("OP_BOOLAND_{}", input);
        let first_input_value = if input.chars().nth(0).unwrap() == '0' { "OP_0" } else { "OP_1" };
        let second_input_value = if input.chars().nth(1).unwrap() == '0' { "OP_0" } else { "OP_1" };
        let output_value = if input.chars().last().unwrap() == '0' { "OP_0" } else { "OP_1" };
        let filled_template = op_booland_template.replace("{}", first_input_value).replace("INSERT_FIRST_INPUT_HERE", first_input_value).replace("INSERT_SECOND_INPUT_HERE", second_input_value).replace("INSERT_OUTPUT_HERE", output_value);
        templates.insert(&template_name, filled_template);
    }

    for input in op_xor_inputs {
        let template_name = format!("OP_XOR_{}", input);
        let first_input_value = if input.chars().nth(0).unwrap() == '0' { "OP_0" } else { "OP_1" };
        let second_input_value = if input.chars().nth(1).unwrap() == '0' { "OP_0" } else { "OP_1" };
        let output_value = if input.chars().last().unwrap() == '0' { "OP_0" } else { "OP_1" };
        let filled_template = op_xor_template.replace("{}", first_input_value).replace("INSERT_FIRST_INPUT_HERE", first_input_value).replace("INSERT_SECOND_INPUT_HERE", second_input_value).replace("INSERT_OUTPUT_HERE", output_value);
        templates.insert(&template_name, filled_template);
    }

    let challenge_scripts: Vec<String> = Vec::new();
}

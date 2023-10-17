use std::collections::HashMap;
use std::fs;
use std::io::Write;
use sha2::{Sha256, Digest};

struct TaprootCircuit {
    wire_settings: HashMap<String, Vec<String>>,
    wire_hashes: HashMap<String, Vec<String>>,
    operations_array: Vec<Vec<String>>,
    initial_commitment_preimages: Vec<Vec<String>>,
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
        // In a real-world Rust application, you'd probably want to return a Result with an error here, 
        // or use some other error handling mechanism instead of printing a message.
        println!("Oops, you entered an invalid bristol circuit! Try again with the whole document, including the first three lines that define the number of gates, number of input bits, and number of output bits.");
    }
    let number_of_preimages_to_expect = arr[0].split_whitespace().nth(1).unwrap_or("0").parse::<u32>().unwrap_or(0);
    let number_of_inputs = arr[1].split_whitespace().nth(1).unwrap_or("0").parse::<u32>().unwrap_or(0);
    let number_of_outputs = arr[2].split_whitespace().nth(1).unwrap_or("0").parse::<u32>().unwrap_or(0);

    arr.drain(0..4);

    (arr, number_of_preimages_to_expect, number_of_inputs, number_of_outputs)
}

async fn set_operations_array(arr: &mut Vec<String>, wire_settings: &mut HashMap<String, Vec<String>>, wire_hashes: &mut HashMap<String, Vec<String>>, operations_array: &mut Vec<Vec<String>>, get_rand: &dyn Fn(u32) -> String, sha256: &dyn Fn(Vec<u8>) -> String, hex_to_bytes: &dyn Fn(String) -> Vec<u8>) {
    for index in 0..arr.len() {
        let gate: Vec<String> = arr[index].split_whitespace().map(|s| s.to_string()).collect();

        match gate.last().unwrap_or(&"".to_string()).as_str() {
            "INV" => {
                let input_preimages = wire_settings.entry(gate[2].clone())
                    .or_insert_with(|| vec![get_rand(32), get_rand(32)]);
                
                let output_preimages = vec![get_rand(32), get_rand(32)];
                
                let input_hashes = vec![
                    sha256(hex_to_bytes(input_preimages[0].clone())).await,
                    sha256(hex_to_bytes(input_preimages[1].clone())).await
                ];
                
                wire_hashes.insert(gate[2].clone(), input_hashes.clone());
                
                let output_hashes = vec![
                    sha256(hex_to_bytes(output_preimages[0].clone())).await,
                    sha256(hex_to_bytes(output_preimages[1].clone())).await
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
                let first_input_preimages = wire_settings.entry(gate[2].clone())
                    .or_insert_with(|| vec![get_rand(32), get_rand(32)]);
            
                let second_input_preimages = wire_settings.entry(gate[3].clone())
                    .or_insert_with(|| vec![get_rand(32), get_rand(32)]);
            
                let output_preimages = vec![get_rand(32), get_rand(32)];
            
                let first_input_hashes = vec![
                    sha256(hex_to_bytes(first_input_preimages[0].clone())).await,
                    sha256(hex_to_bytes(first_input_preimages[1].clone())).await
                ];
                wire_hashes.insert(gate[2].clone(), first_input_hashes.clone());
            
                let second_input_hashes = vec![
                    sha256(hex_to_bytes(second_input_preimages[0].clone())).await,
                    sha256(hex_to_bytes(second_input_preimages[1].clone())).await
                ];
                wire_hashes.insert(gate[3].clone(), second_input_hashes.clone());
            
                let output_hashes = vec![
                    sha256(hex_to_bytes(output_preimages[0].clone())).await,
                    sha256(hex_to_bytes(output_preimages[1].clone())).await
                ];
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
                let first_input_preimages = wire_settings.entry(gate[2].clone())
                    .or_insert_with(|| vec![get_rand(32), get_rand(32)]);
            
                let second_input_preimages = wire_settings.entry(gate[3].clone())
                    .or_insert_with(|| vec![get_rand(32), get_rand(32)]);
            
                let output_preimages = vec![get_rand(32), get_rand(32)];
            
                let first_input_hashes = vec![
                    sha256(hex_to_bytes(first_input_preimages[0].clone())).await,
                    sha256(hex_to_bytes(first_input_preimages[1].clone())).await
                ];
                wire_hashes.insert(gate[2].clone(), first_input_hashes.clone());
            
                let second_input_hashes = vec![
                    sha256(hex_to_bytes(second_input_preimages[0].clone())).await,
                    sha256(hex_to_bytes(second_input_preimages[1].clone())).await
                ];
                wire_hashes.insert(gate[3].clone(), second_input_hashes.clone());
            
                let output_hashes = vec![
                    sha256(hex_to_bytes(output_preimages[0].clone())).await,
                    sha256(hex_to_bytes(output_preimages[1].clone())).await
                ];
                wire_settings.insert(gate[4].clone(), output_preimages.clone());
                wire_hashes.insert(gate[4].clone(), output_hashes.clone());
            
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

impl TaprootCircuit {
    fn new() -> Self {
        TaprootCircuit {
            wire_settings: HashMap::new(),
            wire_hashes: HashMap::new(),
            operations_array: Vec::new(),
            initial_commitment_preimages: Vec::new(),
        }
    }

    async fn generate_bit_commitments(&mut self) {
        for i in 0..64 {
            let key = i.to_string();
            let preimages = self.wire_settings.get(&key).expect("Expected preimages not found");
            
            let hash_0 = sha256(preimages[0].as_bytes());
            let hash_1 = sha256(preimages[1].as_bytes());

            self.initial_commitment_preimages.push(vec![hash_0, hash_1]);
        }
    }

    fn save_data(data: &str, file_name: &str) -> Result<(), std::io::Error> {
        let mut file = fs::File::create(file_name)?;
        file.write_all(data.as_bytes())?;
        Ok(())
    }
}

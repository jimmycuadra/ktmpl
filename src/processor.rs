use lazy_static::lazy_static;
use regex::{Captures, Regex};
use yaml_rust::yaml::{Array, Hash};
use yaml_rust::Yaml;

use crate::parameter::ParamMap;

pub fn process_yaml(yaml: &mut Yaml, parameters: &ParamMap) -> Option<Yaml> {
    match yaml {
        &mut Yaml::Array(ref mut array) => process_array(array, parameters),
        &mut Yaml::Hash(ref mut hash) => process_hash(hash, parameters),
        &mut Yaml::String(ref mut string) => process_string(string, parameters),
        _ => None,
    }
}

fn process_array(array: &mut Array, parameters: &ParamMap) -> Option<Yaml> {
    for value in array {
        if let Some(new_value) = process_yaml(value, parameters) {
            *value = new_value;
        }
    }

    None
}

fn process_hash(hash: &mut Hash, parameters: &ParamMap) -> Option<Yaml> {
    let mut keys_to_replace = Vec::new();

    for (key, value) in hash.iter_mut() {
        let mut key_string = match key {
            Yaml::String(key_string) => key_string.clone(),
            _ => panic!("all hash keys must be strings"),
        };

        if let Some(new_key) = process_string(&mut key_string, parameters) {
            if &new_key != key {
                keys_to_replace.push((key.clone(), new_key));
            }
        }

        if let Some(new_value) = process_yaml(value, parameters) {
            *value = new_value;
        }
    }

    for (key, new_key) in keys_to_replace {
        let value = hash.remove(&key).expect("removing old value while replacing keys");
        hash.insert(new_key, value);
    }

    None
}

fn process_string(string: &mut String, parameters: &ParamMap) -> Option<Yaml> {
    lazy_static! {
        static ref LITERAL_INTERPOLATION: Regex =
            Regex::new(r"\$\({2}([^\)]*)\){2}").expect("Failed to compile regex.");
    }

    lazy_static! {
        static ref STRING_INTERPOLATION: Regex =
            Regex::new(r"\$\(([^\)]*)\)").expect("Failed to compile regex.");
    }

    let interpolate = |captures: &Captures| -> String {
        let key = captures
            .get(1)
            .expect("Failed to extract regex capture group.");

        match parameters.get(key.as_str()) {
            Some(parameter) => parameter.value.clone().unwrap_or("~".to_owned()),
            None => captures
                .get(0)
                .expect("Failed to extract regex match.")
                .as_str()
                .to_owned(),
        }
    };

    let replacement = LITERAL_INTERPOLATION.replace_all(string, &interpolate);

    let contains_literal_replacement = &replacement != string;

    let final_replacement = STRING_INTERPOLATION.replace_all(&replacement, &interpolate);

    let contains_string_replacement = &final_replacement != &replacement;

    if !contains_literal_replacement && !contains_string_replacement {
        None
    } else if contains_literal_replacement && !contains_string_replacement {
        Some(Yaml::from_str(&final_replacement))
    } else {
        Some(Yaml::String(final_replacement.to_string()))
    }
}

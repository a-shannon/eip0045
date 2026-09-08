//! Structural dependency-boundary checks for the B4 Rust validator.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

const WORKSPACE_MANIFEST: &str = include_str!("../../Cargo.toml");
const PACKAGE_MANIFEST: &str = include_str!("../Cargo.toml");
const GENERATOR_MANIFEST: &str = include_str!("../../generator/Cargo.toml");
const METHODS_MANIFEST: &str = include_str!("../../methods/Cargo.toml");
const GUEST_MANIFEST: &str = include_str!("../../methods/guest/Cargo.toml");
const CARGO_LOCK: &str = include_str!("../../Cargo.lock");
const GENERATOR_CARGO_LOCK: &str = include_str!("../../generator/Cargo.lock");
const METHODS_CARGO_LOCK: &str = include_str!("../../methods/Cargo.lock");
const GUEST_CARGO_LOCK: &str = include_str!("../../methods/guest/Cargo.lock");
const NEGATIVE_HANDLER_CONTRACT_SOURCE: &str =
    include_str!("../src/b4_negative_handler_contract.rs");
const NEGATIVE_IO_SOURCE: &str = include_str!("../src/b4_negative_io.rs");
const NEGATIVE_INPUT_SOURCE: &str = include_str!("../src/b4_validator/negative_input.rs");
const RISC0_GIT_URL: &str = "https://github.com/a-shannon/risc0";
const RISC0_REVISION: &str = "227229dc793c215c533cbc0e07911601974a4629";

#[derive(Clone, Debug, Eq, PartialEq)]
enum TomlValue {
    String(String),
    Integer(u64),
    Boolean(bool),
    Array(Vec<Self>),
    InlineTable(BTreeMap<String, Self>),
}

#[derive(Debug, Default)]
struct TomlDocument {
    tables: BTreeMap<String, BTreeMap<String, TomlValue>>,
    array_tables: BTreeMap<String, Vec<BTreeMap<String, TomlValue>>>,
}

#[derive(Clone, Debug)]
enum CurrentTable {
    Standard(String),
    Array { name: String, index: usize },
}

struct TomlParser {
    chars: Vec<char>,
    position: usize,
}

impl TomlParser {
    fn parse(source: &str) -> Result<TomlDocument, String> {
        let mut parser = Self {
            chars: source.chars().collect(),
            position: 0,
        };
        let mut document = TomlDocument::default();
        let mut current = CurrentTable::Standard(String::new());
        document.tables.insert(String::new(), BTreeMap::new());

        while parser.skip_document_trivia() {
            if parser.peek() == Some('[') {
                current = parser.parse_header(&mut document)?;
            } else {
                let key = parser.parse_key('=')?;
                parser.expect('=')?;
                parser.skip_value_trivia();
                let value = parser.parse_value()?;
                parser.finish_assignment()?;
                let table = match &current {
                    CurrentTable::Standard(name) => document
                        .tables
                        .get_mut(name)
                        .expect("current standard table must exist"),
                    CurrentTable::Array { name, index } => document
                        .array_tables
                        .get_mut(name)
                        .and_then(|tables| tables.get_mut(*index))
                        .expect("current array table must exist"),
                };
                if table.insert(key.clone(), value).is_some() {
                    return Err(format!("duplicate key `{key}`"));
                }
            }
        }
        Ok(document)
    }

    fn parse_header(&mut self, document: &mut TomlDocument) -> Result<CurrentTable, String> {
        self.expect('[')?;
        let is_array = self.consume('[');
        let terminator = if is_array { "]]" } else { "]" };
        let name = self.parse_header_key(']')?;
        self.expect(']')?;
        if is_array {
            self.expect(']')?;
        }
        self.finish_assignment()
            .map_err(|error| format!("invalid table header `{name}` ({terminator}): {error}"))?;

        if is_array {
            if document.tables.contains_key(&name) {
                return Err(format!(
                    "array table `{name}` conflicts with a standard table"
                ));
            }
            let tables = document.array_tables.entry(name.clone()).or_default();
            tables.push(BTreeMap::new());
            Ok(CurrentTable::Array {
                name,
                index: tables.len() - 1,
            })
        } else {
            if document.array_tables.contains_key(&name) {
                return Err(format!(
                    "standard table `{name}` conflicts with an array table"
                ));
            }
            if document
                .tables
                .insert(name.clone(), BTreeMap::new())
                .is_some()
            {
                return Err(format!("duplicate standard table `{name}`"));
            }
            Ok(CurrentTable::Standard(name))
        }
    }

    fn parse_key(&mut self, terminator: char) -> Result<String, String> {
        self.skip_horizontal_whitespace();
        let start = self.position;
        while let Some(character) = self.peek() {
            if character == terminator {
                break;
            }
            if character == '\r' || character == '\n' || character == '#' {
                return Err(format!("unterminated key at character {}", self.position));
            }
            self.position += 1;
        }
        if self.peek() != Some(terminator) {
            return Err(format!("missing `{terminator}` after key"));
        }
        let key: String = self.chars[start..self.position].iter().collect();
        let key = key.trim();
        if key.is_empty()
            || !key
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "_.-".contains(character))
        {
            return Err(format!("unsupported or empty bare key `{key}`"));
        }
        Ok(key.to_owned())
    }

    fn parse_header_key(&mut self, terminator: char) -> Result<String, String> {
        self.skip_horizontal_whitespace();
        let start = self.position;
        let mut end = start;
        let mut needs_component = true;

        loop {
            match self.peek() {
                Some(character) if character == terminator => {
                    if needs_component {
                        return Err("unsupported or empty table header key".to_owned());
                    }
                    return Ok(self.chars[start..end].iter().collect());
                }
                Some('\r' | '\n' | '#') => {
                    return Err(format!(
                        "unterminated table header key at character {}",
                        self.position
                    ));
                }
                Some(' ' | '\t') if !needs_component => {
                    self.skip_horizontal_whitespace();
                    if self.peek() == Some(terminator) {
                        return Ok(self.chars[start..end].iter().collect());
                    }
                    return Err(format!(
                        "unsupported table header character at character {}",
                        self.position
                    ));
                }
                Some('.') if !needs_component => {
                    self.position += 1;
                    end = self.position;
                    needs_component = true;
                }
                Some('\'' | '"') if needs_component => {
                    let quote = self
                        .next()
                        .expect("quoted component must begin with a quote");
                    let content_start = self.position;
                    loop {
                        match self.next() {
                            Some(character) if character == quote => break,
                            Some('\\') if quote == '"' => match self.next() {
                                Some('\r' | '\n') | None => {
                                    return Err("unterminated quoted table header key".to_owned());
                                }
                                Some(_) => {}
                            },
                            Some('\r' | '\n') | None => {
                                return Err("unterminated quoted table header key".to_owned());
                            }
                            Some(_) => {}
                        }
                    }
                    if self.position == content_start + 1 {
                        return Err("unsupported or empty table header key".to_owned());
                    }
                    end = self.position;
                    needs_component = false;
                }
                Some(character)
                    if needs_component
                        && (character.is_ascii_alphanumeric() || "_-".contains(character)) =>
                {
                    self.position += 1;
                    while self.peek().is_some_and(|character| {
                        character.is_ascii_alphanumeric() || "_-".contains(character)
                    }) {
                        self.position += 1;
                    }
                    end = self.position;
                    needs_component = false;
                }
                Some(_) => {
                    return Err(format!(
                        "unsupported table header character at character {}",
                        self.position
                    ));
                }
                None => return Err(format!("missing `{terminator}` after table header key")),
            }
        }
    }

    fn parse_value(&mut self) -> Result<TomlValue, String> {
        match self.peek() {
            Some('"') => self.parse_basic_string().map(TomlValue::String),
            Some('\'') => self.parse_literal_string().map(TomlValue::String),
            Some('[') => self.parse_array(),
            Some('{') => self.parse_inline_table(),
            Some(character) if character.is_ascii_digit() => self.parse_integer(),
            Some('t') if self.consume_keyword("true") => Ok(TomlValue::Boolean(true)),
            Some('f') if self.consume_keyword("false") => Ok(TomlValue::Boolean(false)),
            Some(character) => Err(format!(
                "unsupported TOML value beginning with `{character}` at character {}",
                self.position
            )),
            None => Err("missing TOML value at end of document".to_owned()),
        }
    }

    fn parse_basic_string(&mut self) -> Result<String, String> {
        self.expect('"')?;
        let mut output = String::new();
        loop {
            match self.next() {
                Some('"') => return Ok(output),
                Some('\\') => {
                    let escaped = match self.next() {
                        Some('"') => '"',
                        Some('\\') => '\\',
                        Some('n') => '\n',
                        Some('r') => '\r',
                        Some('t') => '\t',
                        Some(other) => {
                            return Err(format!("unsupported TOML escape `\\{other}`"));
                        }
                        None => return Err("unterminated TOML escape".to_owned()),
                    };
                    output.push(escaped);
                }
                Some('\r' | '\n') => {
                    return Err("newline in single-line TOML string".to_owned());
                }
                Some(character) => output.push(character),
                None => return Err("unterminated TOML string".to_owned()),
            }
        }
    }

    fn parse_literal_string(&mut self) -> Result<String, String> {
        self.expect('\'')?;
        let start = self.position;
        while self.peek().is_some_and(|character| character != '\'') {
            if matches!(self.peek(), Some('\r' | '\n')) {
                return Err("newline in single-line TOML literal string".to_owned());
            }
            self.position += 1;
        }
        self.expect('\'')?;
        Ok(self.chars[start..self.position - 1].iter().collect())
    }

    fn parse_integer(&mut self) -> Result<TomlValue, String> {
        let start = self.position;
        while self
            .peek()
            .is_some_and(|character| character.is_ascii_digit())
        {
            self.position += 1;
        }
        let digits: String = self.chars[start..self.position].iter().collect();
        digits
            .parse::<u64>()
            .map(TomlValue::Integer)
            .map_err(|error| format!("invalid unsigned TOML integer `{digits}`: {error}"))
    }

    fn parse_array(&mut self) -> Result<TomlValue, String> {
        self.expect('[')?;
        let mut values = Vec::new();
        loop {
            self.skip_value_trivia();
            if self.consume(']') {
                return Ok(TomlValue::Array(values));
            }
            values.push(self.parse_value()?);
            self.skip_value_trivia();
            if self.consume(']') {
                return Ok(TomlValue::Array(values));
            }
            self.expect(',')?;
        }
    }

    fn parse_inline_table(&mut self) -> Result<TomlValue, String> {
        self.expect('{')?;
        let mut entries = BTreeMap::new();
        loop {
            self.skip_horizontal_whitespace();
            if self.consume('}') {
                return Ok(TomlValue::InlineTable(entries));
            }
            let key = self.parse_key('=')?;
            self.expect('=')?;
            self.skip_horizontal_whitespace();
            let value = self.parse_value()?;
            if entries.insert(key.clone(), value).is_some() {
                return Err(format!("duplicate inline-table key `{key}`"));
            }
            self.skip_horizontal_whitespace();
            if self.consume('}') {
                return Ok(TomlValue::InlineTable(entries));
            }
            self.expect(',')?;
        }
    }

    fn finish_assignment(&mut self) -> Result<(), String> {
        self.skip_horizontal_whitespace();
        if self.consume('#') {
            while self
                .peek()
                .is_some_and(|character| !matches!(character, '\r' | '\n'))
            {
                self.position += 1;
            }
        }
        match self.peek() {
            Some('\r') => {
                self.position += 1;
                let _ = self.consume('\n');
                Ok(())
            }
            Some('\n') => {
                self.position += 1;
                Ok(())
            }
            None => Ok(()),
            Some(character) => Err(format!(
                "unexpected `{character}` after TOML assignment at character {}",
                self.position
            )),
        }
    }

    fn skip_document_trivia(&mut self) -> bool {
        loop {
            while self.peek().is_some_and(char::is_whitespace) {
                self.position += 1;
            }
            if !self.consume('#') {
                return self.peek().is_some();
            }
            while self
                .peek()
                .is_some_and(|character| !matches!(character, '\r' | '\n'))
            {
                self.position += 1;
            }
        }
    }

    fn skip_value_trivia(&mut self) {
        loop {
            while self.peek().is_some_and(char::is_whitespace) {
                self.position += 1;
            }
            if !self.consume('#') {
                return;
            }
            while self
                .peek()
                .is_some_and(|character| !matches!(character, '\r' | '\n'))
            {
                self.position += 1;
            }
        }
    }

    fn skip_horizontal_whitespace(&mut self) {
        while self
            .peek()
            .is_some_and(|character| matches!(character, ' ' | '\t'))
        {
            self.position += 1;
        }
    }

    fn consume_keyword(&mut self, keyword: &str) -> bool {
        let end = self.position + keyword.chars().count();
        if self.chars.get(self.position..end).is_some_and(|slice| {
            slice.iter().copied().eq(keyword.chars())
                && self
                    .chars
                    .get(end)
                    .is_none_or(|next| !next.is_ascii_alphanumeric() && *next != '_')
        }) {
            self.position = end;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, expected: char) -> Result<(), String> {
        match self.next() {
            Some(actual) if actual == expected => Ok(()),
            Some(actual) => Err(format!(
                "expected `{expected}`, found `{actual}` at character {}",
                self.position - 1
            )),
            None => Err(format!("expected `{expected}`, found end of document")),
        }
    }

    fn consume(&mut self, expected: char) -> bool {
        if self.peek() == Some(expected) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.position).copied()
    }

    fn next(&mut self) -> Option<char> {
        let value = self.peek();
        if value.is_some() {
            self.position += 1;
        }
        value
    }
}

fn parse_toml(label: &str, source: &str) -> TomlDocument {
    TomlParser::parse(source)
        .unwrap_or_else(|error| panic!("{label} is not accepted TOML: {error}"))
}

fn table<'a>(document: &'a TomlDocument, name: &str) -> &'a BTreeMap<String, TomlValue> {
    document
        .tables
        .get(name)
        .unwrap_or_else(|| panic!("missing TOML table [{name}]"))
}

fn inline_table<'a>(
    table: &'a BTreeMap<String, TomlValue>,
    key: &str,
) -> &'a BTreeMap<String, TomlValue> {
    match table.get(key) {
        Some(TomlValue::InlineTable(value)) => value,
        value => panic!("`{key}` must be an inline table, found {value:?}"),
    }
}

fn string_value<'a>(table: &'a BTreeMap<String, TomlValue>, key: &str) -> &'a str {
    match table.get(key) {
        Some(TomlValue::String(value)) => value,
        value => panic!("`{key}` must be a string, found {value:?}"),
    }
}

fn string_set<'a>(table: &'a BTreeMap<String, TomlValue>, key: &str) -> BTreeSet<&'a str> {
    match table.get(key) {
        Some(TomlValue::Array(values)) => {
            let strings: BTreeSet<_> = values
                .iter()
                .map(|value| match value {
                    TomlValue::String(value) => value.as_str(),
                    other => panic!("`{key}` contains a non-string value: {other:?}"),
                })
                .collect();
            assert_eq!(
                strings.len(),
                values.len(),
                "`{key}` contains duplicate feature entries"
            );
            strings
        }
        value => panic!("`{key}` must be an array, found {value:?}"),
    }
}

fn expected_risc0_dependency(features: &[&str], optional: bool) -> BTreeMap<String, TomlValue> {
    let mut expected = BTreeMap::from([
        ("default-features".to_owned(), TomlValue::Boolean(false)),
        (
            "git".to_owned(),
            TomlValue::String(RISC0_GIT_URL.to_owned()),
        ),
        (
            "rev".to_owned(),
            TomlValue::String(RISC0_REVISION.to_owned()),
        ),
    ]);
    if !features.is_empty() {
        expected.insert(
            "features".to_owned(),
            TomlValue::Array(
                features
                    .iter()
                    .map(|feature| TomlValue::String((*feature).to_owned()))
                    .collect(),
            ),
        );
    }
    if optional {
        expected.insert("optional".to_owned(), TomlValue::Boolean(true));
    }
    expected
}

#[test]
fn validator_dependencies_are_structurally_pinned_and_verification_only() {
    let workspace = parse_toml("workspace Cargo.toml", WORKSPACE_MANIFEST);
    let dependencies = table(&workspace, "workspace.dependencies");
    let expected = [
        ("risc0-binfmt", vec!["std"]),
        ("risc0-circuit-recursion", Vec::new()),
        ("risc0-zkp", Vec::new()),
        ("risc0-zkvm", vec!["disable-dev-mode"]),
        ("risc0-zkvm-platform", vec!["export-syscalls"]),
    ];

    let actual_risc0_names: BTreeSet<&str> = dependencies
        .keys()
        .filter(|name| name.starts_with("risc0-"))
        .map(String::as_str)
        .collect();
    let expected_risc0_names: BTreeSet<&str> = expected.iter().map(|(name, _)| *name).collect();
    assert_eq!(
        actual_risc0_names, expected_risc0_names,
        "workspace RISC0 direct dependency set drift"
    );

    for (name, features) in expected {
        assert_eq!(
            inline_table(dependencies, name),
            &expected_risc0_dependency(&features, false),
            "workspace dependency policy drift for {name}"
        );
    }
}

#[test]
fn every_eip_workspace_uses_the_one_reviewed_risc0_build_source() {
    let cases: [(&str, &str, &str, &[(&str, &[&str], bool)]); 3] = [
        (
            "generator Cargo.toml",
            GENERATOR_MANIFEST,
            "dependencies",
            &[
                ("risc0-binfmt", &["std"], false),
                ("risc0-core", &[], false),
                ("risc0-zkp", &[], false),
                ("risc0-zkvm", &["disable-dev-mode"], false),
            ],
        ),
        (
            "methods Cargo.toml",
            METHODS_MANIFEST,
            "build-dependencies",
            &[("risc0-build", &[], true)],
        ),
        (
            "guest Cargo.toml",
            GUEST_MANIFEST,
            "dependencies",
            &[
                ("risc0-circuit-recursion", &[], false),
                ("risc0-zkvm", &[], false),
            ],
        ),
    ];

    for (label, source, dependency_table, expected) in cases {
        let manifest = parse_toml(label, source);
        let dependencies = table(&manifest, dependency_table);
        let actual_names = dependencies
            .keys()
            .filter(|name| name.starts_with("risc0-"))
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let expected_names = expected
            .iter()
            .map(|(name, _, _)| *name)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            actual_names, expected_names,
            "{label} RISC Zero direct dependency set drift"
        );
        for (name, features, optional) in expected {
            assert_eq!(
                inline_table(dependencies, name),
                &expected_risc0_dependency(features, *optional),
                "{label} build-source policy drift for {name}"
            );
        }
    }
}

#[test]
fn policy_toml_parser_accepts_literal_quoted_target_table_segments() {
    let parsed = TomlParser::parse(
        "[target.'cfg(windows)'.dependencies]\n\
         winapi-util = { workspace = true, optional = true }\n",
    )
    .unwrap();
    assert!(
        parsed
            .tables
            .contains_key("target.'cfg(windows)'.dependencies")
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one contiguous assertion matrix keeps the complete feature/dependency closure auditable"
)]
fn validator_features_and_optional_dependencies_are_structurally_closed() {
    let workspace = parse_toml("workspace Cargo.toml", WORKSPACE_MANIFEST);
    let package = parse_toml("reproduction Cargo.toml", PACKAGE_MANIFEST);
    let features = table(&package, "features");
    assert_eq!(
        string_set(features, "profile"),
        BTreeSet::from(["dep:blake2", "dep:risc0-binfmt", "dep:risc0-zkvm-platform"]),
        "profile feature closure drift"
    );
    assert_eq!(
        string_set(features, "receipt-oracle-codec"),
        BTreeSet::from(["dep:bincode"]),
        "receipt-oracle codec feature closure drift"
    );
    assert_eq!(
        string_set(features, "receipt-oracle"),
        BTreeSet::from([
            "receipt-oracle-codec",
            "dep:risc0-circuit-recursion",
            "dep:risc0-zkp",
            "dep:risc0-zkvm",
        ]),
        "receipt-oracle feature closure drift"
    );
    assert_eq!(
        string_set(features, "materializer-replay"),
        BTreeSet::from(["positive-gate", "receipt-oracle", "dep:risc0-zkp"]),
        "materializer replay feature closure drift"
    );
    assert_eq!(
        string_set(features, "b4-terminal-evidence-packet"),
        BTreeSet::from(["validator", "dep:rustix", "dep:winapi-util"]),
        "terminal evidence packet feature closure drift"
    );
    assert_eq!(
        string_set(features, "b4-terminal-evidence-publication"),
        BTreeSet::from(["b4-terminal-evidence-packet", "dep:renamore"]),
        "terminal evidence publication feature closure drift"
    );
    for feature in [
        "b4-terminal-evidence-packet",
        "b4-terminal-evidence-publication",
    ] {
        assert!(
            !string_set(features, "default").contains(feature),
            "{feature} must remain opt-in"
        );
    }
    assert_eq!(
        string_set(features, "negative-ancestry-publication"),
        BTreeSet::from([
            "positive-gate",
            "receipt-oracle",
            "recursive-ancestry",
            "dep:renamore",
            "dep:rustix",
            "dep:winapi-util",
        ]),
    );
    assert_eq!(
        string_set(features, "negative-materialization-set"),
        BTreeSet::from([
            "negative-ancestry-publication",
            "b4-terminal-evidence-packet",
            "materializer-replay",
        ]),
    );
    assert!(
        !string_set(features, "default").contains("negative-materialization-set"),
        "negative-materialization-set must remain opt-in"
    );
    assert_eq!(
        string_set(features, "recursive-ancestry"),
        BTreeSet::from(["profile", "dep:risc0-zkvm", "risc0-zkvm/std",]),
        "recursive ancestry feature closure drift"
    );
    assert_eq!(
        string_set(features, "validator"),
        BTreeSet::from([
            "profile",
            "receipt-oracle",
            "recursive-ancestry",
            "dep:clap",
            "dep:risc0-zkp",
            "dep:rustix"
        ]),
        "validator feature closure drift"
    );

    let dependencies = table(&package, "dependencies");
    let expected_risc0_names = BTreeSet::from([
        "risc0-binfmt",
        "risc0-circuit-recursion",
        "risc0-zkp",
        "risc0-zkvm",
        "risc0-zkvm-platform",
    ]);
    let actual_risc0_names: BTreeSet<&str> = dependencies
        .keys()
        .filter(|name| name.starts_with("risc0-"))
        .map(String::as_str)
        .collect();
    assert_eq!(
        actual_risc0_names, expected_risc0_names,
        "package RISC0 direct dependency set drift"
    );

    let expected_optional_workspace = BTreeMap::from([
        ("optional".to_owned(), TomlValue::Boolean(true)),
        ("workspace".to_owned(), TomlValue::Boolean(true)),
    ]);
    for name in expected_risc0_names {
        assert_eq!(
            inline_table(dependencies, name),
            &expected_optional_workspace,
            "package dependency must remain optional and workspace-inherited: {name}"
        );
    }

    assert_eq!(
        inline_table(dependencies, "rustix"),
        &expected_optional_workspace,
        "rustix must remain optional and workspace-inherited"
    );
    assert_eq!(
        inline_table(dependencies, "renamore"),
        &expected_optional_workspace,
        "renamore must remain optional and workspace-inherited"
    );
    assert!(
        PACKAGE_MANIFEST.contains("winapi-util = { workspace = true, optional = true }"),
        "winapi-util must remain an optional workspace dependency"
    );
    assert_eq!(
        inline_table(table(&workspace, "workspace.dependencies"), "rustix"),
        &BTreeMap::from([
            ("default-features".to_owned(), TomlValue::Boolean(false)),
            (
                "features".to_owned(),
                TomlValue::Array(vec![
                    TomlValue::String("std".to_owned()),
                    TomlValue::String("fs".to_owned()),
                ]),
            ),
            ("version".to_owned(), TomlValue::String("=1.1.4".to_owned())),
        ]),
        "workspace rustix dependency policy drift"
    );
}

#[test]
fn generator_negative_materialization_handler_owns_the_fixed_proof_provider() {
    let generator = parse_toml("generator Cargo.toml", GENERATOR_MANIFEST);
    let features = table(&generator, "features");
    let handler = string_set(features, "b4-negative-materialization-handler");
    assert_eq!(
        handler,
        BTreeSet::from([
            "b4-campaign-executor",
            "embedded-method",
            "eip-0045-reproduction/negative-materialization-set",
        ]),
        "negative materialization handler feature closure drift"
    );
    assert!(
        !string_set(features, "default").contains("b4-negative-materialization-handler"),
        "negative materialization handler must remain opt-in"
    );
    assert_eq!(
        string_set(features, "embedded-method"),
        BTreeSet::from(["eip-0045-methods/embed-methods", "proof-generation"]),
        "fixed materialization proof provider must own both the embedded guest and proof capability"
    );
}

#[test]
fn generator_campaign_executor_test_lane_excludes_the_proof_kernel_closure() {
    let generator = parse_toml("generator Cargo.toml", GENERATOR_MANIFEST);
    let features = table(&generator, "features");
    let campaign_executor = string_set(features, "b4-campaign-executor");
    let forbidden = [
        "embedded-method",
        "proof-generation",
        "eip-0045-methods/embed-methods",
        "risc0-zkvm/prove",
    ];
    let is_kernel_free = |closure: &BTreeSet<&str>| {
        forbidden
            .iter()
            .all(|feature| !closure.contains(feature))
    };

    assert!(
        is_kernel_free(&campaign_executor),
        "b4-campaign-executor must not activate the embedded proof-kernel closure"
    );
    for injected in forbidden {
        let mut mutant = campaign_executor.clone();
        mutant.insert(injected);
        assert!(
            !is_kernel_free(&mutant),
            "feature-closure guard accepted injected `{injected}`"
        );
    }
}

#[test]
fn cargo_lock_has_one_pinned_resolution_for_every_risc0_dependency() {
    let lock = parse_toml("Cargo.lock", CARGO_LOCK);
    let packages = lock
        .array_tables
        .get("package")
        .expect("Cargo.lock must contain [[package]] entries");
    let expected_source = format!("git+{RISC0_GIT_URL}?rev={RISC0_REVISION}#{RISC0_REVISION}");
    let expected_direct_versions = BTreeMap::from([
        ("risc0-binfmt", "3.0.4"),
        ("risc0-circuit-recursion", "4.0.4"),
        ("risc0-zkp", "3.0.4"),
        ("risc0-zkvm", "3.0.5"),
        ("risc0-zkvm-platform", "2.2.2"),
    ]);

    for (name, expected_version) in &expected_direct_versions {
        let resolutions: Vec<_> = packages
            .iter()
            .filter(|package| string_value(package, "name") == *name)
            .collect();
        assert_eq!(
            resolutions.len(),
            1,
            "Cargo.lock must contain exactly one resolution for {name}"
        );
        assert_eq!(
            string_value(resolutions[0], "version"),
            *expected_version,
            "locked version drift for immutable RISC0 revision: {name}"
        );
        assert_eq!(
            string_value(resolutions[0], "source"),
            expected_source,
            "locked source drift for {name}"
        );
    }

    let all_risc0_packages: Vec<_> = packages
        .iter()
        .filter(|package| string_value(package, "name").starts_with("risc0-"))
        .collect();
    assert!(
        !all_risc0_packages.is_empty(),
        "Cargo.lock contains no RISC0 packages"
    );
    for package in all_risc0_packages {
        assert_eq!(
            string_value(package, "source"),
            expected_source,
            "alternate RISC0 source or revision in Cargo.lock for {}",
            string_value(package, "name")
        );
    }

    for (label, source) in [
        ("generator Cargo.lock", GENERATOR_CARGO_LOCK),
        ("methods Cargo.lock", METHODS_CARGO_LOCK),
        ("guest Cargo.lock", GUEST_CARGO_LOCK),
    ] {
        let lock = parse_toml(label, source);
        let packages = lock
            .array_tables
            .get("package")
            .unwrap_or_else(|| panic!("{label} must contain [[package]] entries"));
        let risc0_packages = packages
            .iter()
            .filter(|package| string_value(package, "name").starts_with("risc0-"))
            .collect::<Vec<_>>();
        assert!(
            !risc0_packages.is_empty(),
            "{label} contains no RISC Zero package"
        );
        for package in risc0_packages {
            assert_eq!(
                string_value(package, "source"),
                expected_source,
                "{label} contains an alternate RISC Zero source for {}",
                string_value(package, "name")
            );
        }
    }

    let rustix_resolutions: Vec<_> = packages
        .iter()
        .filter(|package| string_value(package, "name") == "rustix")
        .collect();
    assert_eq!(
        rustix_resolutions.len(),
        1,
        "Cargo.lock must contain exactly one rustix resolution"
    );
    assert_eq!(
        string_value(rustix_resolutions[0], "version"),
        "1.1.4",
        "locked rustix version drift"
    );
    assert_eq!(
        string_value(rustix_resolutions[0], "source"),
        "registry+https://github.com/rust-lang/crates.io-index",
        "locked rustix source drift"
    );
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RustToken {
    Identifier(String),
    Symbol(char),
}

fn skip_block_comment(chars: &[char], mut position: usize) -> usize {
    let mut depth = 1_u32;
    while depth != 0 && position < chars.len() {
        if chars.get(position) == Some(&'/') && chars.get(position + 1) == Some(&'*') {
            depth += 1;
            position += 2;
        } else if chars.get(position) == Some(&'*') && chars.get(position + 1) == Some(&'/') {
            depth -= 1;
            position += 2;
        } else {
            position += 1;
        }
    }
    position
}

fn skip_basic_rust_string(chars: &[char], mut position: usize) -> usize {
    while position < chars.len() {
        if chars[position] == '\\' {
            position = (position + 2).min(chars.len());
        } else if chars[position] == '"' {
            return position + 1;
        } else {
            position += 1;
        }
    }
    position
}

fn skip_raw_rust_string(chars: &[char], position: usize) -> Option<usize> {
    if chars.get(position) != Some(&'r') || chars.get(position + 1) != Some(&'#') {
        return None;
    }
    let mut hashes = 1_usize;
    let mut cursor = position + 2;
    while chars.get(cursor) == Some(&'#') {
        hashes += 1;
        cursor += 1;
    }
    if chars.get(cursor) != Some(&'"') {
        return None;
    }
    cursor += 1;
    loop {
        let end_quote = chars[cursor..]
            .iter()
            .position(|candidate| *candidate == '"')
            .map(|offset| cursor + offset)?;
        if (1..=hashes).all(|offset| chars.get(end_quote + offset) == Some(&'#')) {
            return Some(end_quote + hashes + 1);
        }
        cursor = end_quote + 1;
    }
}

fn skip_rust_character(chars: &[char], position: usize) -> Option<usize> {
    if chars.get(position) != Some(&'\'') {
        return None;
    }
    if chars.get(position + 1) == Some(&'\\') {
        return chars
            .get(position + 3..)?
            .iter()
            .take(12)
            .position(|candidate| *candidate == '\'')
            .map(|closing_offset| position + closing_offset + 4);
    }
    (chars.get(position + 2) == Some(&'\'')).then_some(position + 3)
}

fn rust_tokens(source: &str) -> Vec<RustToken> {
    let chars: Vec<char> = source.chars().collect();
    let mut tokens = Vec::new();
    let mut position = 0;
    while position < chars.len() {
        let character = chars[position];
        if character.is_whitespace() {
            position += 1;
        } else if character == '/' && chars.get(position + 1) == Some(&'/') {
            position += 2;
            while chars
                .get(position)
                .is_some_and(|next| !matches!(next, '\r' | '\n'))
            {
                position += 1;
            }
        } else if character == '/' && chars.get(position + 1) == Some(&'*') {
            position = skip_block_comment(&chars, position + 2);
        } else if character == '"' {
            position = skip_basic_rust_string(&chars, position + 1);
        } else if character == '\'' {
            if let Some(after_character) = skip_rust_character(&chars, position) {
                position = after_character;
            } else {
                tokens.push(RustToken::Symbol(character));
                position += 1;
            }
        } else if let Some(after_raw_string) = skip_raw_rust_string(&chars, position) {
            position = after_raw_string;
        } else if character.is_ascii_alphabetic() || character == '_' {
            let start = position;
            position += 1;
            while chars
                .get(position)
                .is_some_and(|next| next.is_ascii_alphanumeric() || *next == '_')
            {
                position += 1;
            }
            tokens.push(RustToken::Identifier(
                chars[start..position].iter().collect(),
            ));
        } else {
            tokens.push(RustToken::Symbol(character));
            position += 1;
        }
    }
    tokens
}

fn is_identifier(token: Option<&RustToken>, expected: &str) -> bool {
    matches!(token, Some(RustToken::Identifier(actual)) if actual == expected)
}

fn is_symbol(token: Option<&RustToken>, expected: char) -> bool {
    matches!(token, Some(RustToken::Symbol(actual)) if *actual == expected)
}

fn function_parameter_lists(tokens: &[RustToken], function_name: &str) -> Vec<Vec<RustToken>> {
    let mut parameters = Vec::new();
    let mut position = 0;
    while position + 2 < tokens.len() {
        if !is_identifier(tokens.get(position), "fn")
            || !is_identifier(tokens.get(position + 1), function_name)
            || !is_symbol(tokens.get(position + 2), '(')
        {
            position += 1;
            continue;
        }
        let start = position + 3;
        let mut cursor = start;
        let mut depth = 1_u32;
        while cursor < tokens.len() && depth != 0 {
            if is_symbol(tokens.get(cursor), '(') {
                depth += 1;
            } else if is_symbol(tokens.get(cursor), ')') {
                depth -= 1;
            }
            cursor += 1;
        }
        assert_eq!(depth, 0, "unterminated parameter list for {function_name}");
        parameters.push(tokens[start..cursor - 1].to_vec());
        position = cursor;
    }
    parameters
}

fn strip_exact_cfg_test_items(tokens: &[RustToken]) -> Vec<RustToken> {
    let mut output = Vec::new();
    let mut position = 0;
    while position < tokens.len() {
        let exact_cfg_test = is_symbol(tokens.get(position), '#')
            && is_symbol(tokens.get(position + 1), '[')
            && is_identifier(tokens.get(position + 2), "cfg")
            && is_symbol(tokens.get(position + 3), '(')
            && is_identifier(tokens.get(position + 4), "test")
            && is_symbol(tokens.get(position + 5), ')')
            && is_symbol(tokens.get(position + 6), ']');
        if !exact_cfg_test {
            output.push(tokens[position].clone());
            position += 1;
            continue;
        }

        position += 7;
        while position < tokens.len() && !is_symbol(tokens.get(position), '{') {
            if is_symbol(tokens.get(position), ';') {
                position += 1;
                break;
            }
            position += 1;
        }
        if position >= tokens.len() || !is_symbol(tokens.get(position), '{') {
            continue;
        }
        let mut depth = 1_u32;
        position += 1;
        while depth != 0 && position < tokens.len() {
            if is_symbol(tokens.get(position), '{') {
                depth += 1;
            } else if is_symbol(tokens.get(position), '}') {
                depth -= 1;
            }
            position += 1;
        }
    }
    output
}

fn contains_platform_syscall_reference(source: &str) -> bool {
    let tokens = strip_exact_cfg_test_items(&rust_tokens(source));
    let mut aliases = BTreeSet::from(["risc0_zkvm_platform".to_owned()]);

    for window in tokens.windows(3) {
        if is_identifier(window.first(), "risc0_zkvm_platform")
            && is_identifier(window.get(1), "as")
            && let Some(RustToken::Identifier(alias)) = window.get(2)
        {
            aliases.insert(alias.clone());
        }
    }
    for (position, window) in tokens.windows(4).enumerate() {
        if is_identifier(window.first(), "risc0_zkvm_platform")
            && is_symbol(window.get(1), ':')
            && is_symbol(window.get(2), ':')
            && is_symbol(window.get(3), '{')
        {
            let mut depth = 1_u32;
            let mut cursor = position + 4;
            while depth != 0 && cursor < tokens.len() {
                if is_symbol(tokens.get(cursor), '{') {
                    depth += 1;
                } else if is_symbol(tokens.get(cursor), '}') {
                    depth -= 1;
                } else if depth == 1
                    && is_identifier(tokens.get(cursor), "self")
                    && is_identifier(tokens.get(cursor + 1), "as")
                    && let Some(RustToken::Identifier(alias)) = tokens.get(cursor + 2)
                {
                    aliases.insert(alias.clone());
                }
                cursor += 1;
            }
        }
    }

    for (position, token) in tokens.iter().enumerate() {
        let RustToken::Identifier(identifier) = token else {
            continue;
        };
        if !aliases.contains(identifier)
            || !is_symbol(tokens.get(position + 1), ':')
            || !is_symbol(tokens.get(position + 2), ':')
        {
            continue;
        }
        if is_identifier(tokens.get(position + 3), "syscall") {
            return true;
        }
        if !is_symbol(tokens.get(position + 3), '{') {
            continue;
        }
        let mut depth = 1_u32;
        let mut cursor = position + 4;
        while depth != 0 && cursor < tokens.len() {
            if is_symbol(tokens.get(cursor), '{') {
                depth += 1;
            } else if is_symbol(tokens.get(cursor), '}') {
                depth -= 1;
            } else if depth == 1 && is_identifier(tokens.get(cursor), "syscall") {
                return true;
            }
            cursor += 1;
        }
    }
    false
}

fn runtime_rust_sources(root: &Path) -> Vec<PathBuf> {
    fn visit(directory: &Path, files: &mut Vec<PathBuf>) {
        let mut entries: Vec<_> = fs::read_dir(directory)
            .unwrap_or_else(|error| {
                panic!(
                    "cannot read source directory {}: {error}",
                    directory.display()
                )
            })
            .map(|entry| entry.expect("cannot read source-directory entry"))
            .collect();
        entries.sort_by_key(std::fs::DirEntry::path);
        for entry in entries {
            let path = entry.path();
            if path.is_dir() {
                let excluded = path
                    .file_name()
                    .is_some_and(|name| matches!(name.to_str(), Some("tests" | "docs" | "target")));
                if !excluded {
                    visit(&path, files);
                }
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                files.push(path);
            }
        }
    }

    let mut files = Vec::new();
    visit(root, &mut files);
    files
}

#[test]
fn runtime_sources_do_not_reference_platform_syscalls() {
    let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let sources = runtime_rust_sources(&source_root);
    assert!(
        !sources.is_empty(),
        "runtime source scan found no Rust files"
    );
    let offenders: Vec<_> = sources
        .into_iter()
        .filter(|path| {
            let source = fs::read_to_string(path)
                .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
            contains_platform_syscall_reference(&source)
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "runtime source references risc0_zkvm_platform syscall APIs: {offenders:?}"
    );
}

#[test]
fn production_negative_custody_api_accepts_only_the_root_path() {
    let tokens = rust_tokens(NEGATIVE_INPUT_SOURCE);
    let parameters = function_parameter_lists(&tokens, "load_negative_verifier_root");
    assert_eq!(
        parameters.len(),
        1,
        "production negative-custody entry point must occur exactly once"
    );
    assert_eq!(
        parameters[0],
        vec![
            RustToken::Identifier("root".to_owned()),
            RustToken::Symbol(':'),
            RustToken::Symbol('&'),
            RustToken::Identifier("Path".to_owned()),
        ],
        "production negative-custody entry point gained injectable authority"
    );
    for forbidden in ["contract", "resolver", "authority", "handler"] {
        assert!(
            !parameters[0]
                .iter()
                .any(|token| is_identifier(Some(token), forbidden)),
            "production negative-custody API exposes `{forbidden}`"
        );
    }
}

#[test]
fn negative_dispatch_and_custody_have_one_table_authority() {
    assert!(
        NEGATIVE_HANDLER_CONTRACT_SOURCE
            .contains("const B4_NEGATIVE_HANDLER_CONTRACTS: &[B4NegativeHandlerContract]"),
        "canonical negative handler-contract table is absent"
    );
    for (label, source, forbidden) in [
        (
            "negative input custody",
            NEGATIVE_INPUT_SOURCE,
            "FROZEN_CUSTODY_CONTRACTS",
        ),
        (
            "neutral negative I/O",
            NEGATIVE_IO_SOURCE,
            "FROZEN_CONTEXT_CARDINALITIES",
        ),
    ] {
        assert!(
            !source.contains(forbidden),
            "{label} reintroduced an independent handler authority"
        );
    }
}

#[test]
fn syscall_scanner_ignores_constants_comments_strings_and_test_only_items() {
    for allowed in [
        "use risc0_zkvm_platform::WORD_SIZE;",
        "use risc0_zkvm_platform::{WORD_SIZE, PAGE_SIZE};",
        "let words = risc0_zkvm_platform::WORD_SIZE;",
        "fn borrow<'a>(value: &'a str) -> &'a str { value }",
        "// risc0_zkvm_platform::syscall::sys_alloc_words(1);",
        "const TEXT: &str = \"risc0_zkvm_platform::syscall\";",
        "const RAW: &str = r#\"risc0_zkvm_platform::syscall\"#;",
        "#[cfg(test)] mod tests { fn probe() { risc0_zkvm_platform::syscall::x(); } }",
    ] {
        assert!(
            !contains_platform_syscall_reference(allowed),
            "allowed source was falsely classified: {allowed}"
        );
    }

    for forbidden in [
        "risc0_zkvm_platform::syscall::sys_alloc_words(1);",
        "use risc0_zkvm_platform::syscall;",
        "use risc0_zkvm_platform::{WORD_SIZE, syscall};",
        "use risc0_zkvm_platform as platform; platform::syscall::x();",
        "use risc0_zkvm_platform::{self as platform, WORD_SIZE}; platform::syscall::x();",
        "fn probe<'a>() { risc0_zkvm_platform::syscall::x(); }",
        "fn probe() { let quote = '\\''; risc0_zkvm_platform::syscall::x(); }",
    ] {
        assert!(
            contains_platform_syscall_reference(forbidden),
            "platform syscall reference escaped classification: {forbidden}"
        );
    }
}
